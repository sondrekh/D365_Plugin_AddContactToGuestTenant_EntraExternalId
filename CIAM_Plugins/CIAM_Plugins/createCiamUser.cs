using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Linq;
using Microsoft.Xrm.Sdk;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CIAMPlugins
{
    /// <summary>
    /// Plugin to automatically provision users in Microsoft Entra External ID (CIAM)
    /// and assign them to a security group for application access.
    /// </summary>
    public class CreateCiamUser : IPlugin
    {
        private readonly string _secureConfig;

        public CreateCiamUser(string unsecureConfig, string secureConfig)
        {
            _secureConfig = secureConfig;
        }

        public void Execute(IServiceProvider serviceProvider)
        {
            ITracingService tracer = (ITracingService)serviceProvider.GetService(typeof(ITracingService));
            IPluginExecutionContext context = (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));

            // Ensure TLS 1.2 for communication with Microsoft Graph
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // Prevent infinite loops
            if (context.Depth > 1) return;

            if (string.IsNullOrEmpty(_secureConfig))
            {
                tracer.Trace("Critical: Secure configuration is missing.");
                return;
            }

            if (!context.InputParameters.Contains("Target") || !(context.InputParameters["Target"] is Entity targetEntity))
                return;

            // Use PostImage for robust data access, fallback to Target
            Entity contact = context.PostEntityImages.Contains("PostImage")
                ? context.PostEntityImages["PostImage"]
                : targetEntity;

            string email = contact.GetAttributeValue<string>("emailaddress1");
            if (string.IsNullOrEmpty(email))
            {
                tracer.Trace("Execution aborted: Contact is missing an email address.");
                return;
            }

            try
            {
                JObject config = JObject.Parse(_secureConfig);
                string tenantId = config["tenantId"]?.ToString();
                string clientId = config["clientId"]?.ToString();
                string clientSecret = config["clientSecret"]?.ToString();
                string domain = config["tenantDomain"]?.ToString();
                string groupId = config["groupId"]?.ToString();

                if (new[] { tenantId, clientId, clientSecret, domain }.Any(string.IsNullOrEmpty))
                {
                    throw new InvalidPluginExecutionException("Configuration Error: Missing required fields in Secure Configuration.");
                }

                tracer.Trace($"Initiating CIAM provisioning for: {email}");

                using (var httpClient = new HttpClient())
                {
                    httpClient.Timeout = TimeSpan.FromSeconds(60);

                    string accessToken = GetGraphAccessToken(httpClient, tenantId, clientId, clientSecret);

                    // 1. Attempt to create the user
                    string userId = ProvisionUserInGraph(httpClient, accessToken, email, contact, domain, tracer);

                    // 2. Add to security group if configured
                    if (!string.IsNullOrEmpty(groupId) && !string.IsNullOrEmpty(userId))
                    {
                        AddUserToGroup(httpClient, accessToken, userId, groupId, tracer);
                    }
                }
            }
            catch (InvalidPluginExecutionException ex)
            {
                // Directly re-throw to ensure the UI catches the user-friendly message
                throw ex;
            }
            catch (Exception ex)
            {
                tracer.Trace($"Plugin failed: {ex.Message}");
                throw new InvalidPluginExecutionException($"CIAM Provisioning Error: {ex.Message}", ex);
            }
        }

        private string GetGraphAccessToken(HttpClient client, string tenantId, string clientId, string clientSecret)
        {
            var tokenUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
            var requestBody = $"client_id={clientId}&scope=https://graph.microsoft.com/.default&client_secret={clientSecret}&grant_type=client_credentials";

            var response = client.PostAsync(tokenUrl, new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded")).Result;
            var content = response.Content.ReadAsStringAsync().Result;

            if (!response.IsSuccessStatusCode)
                throw new Exception($"Graph Authentication failed: {response.ReasonPhrase}. Details: {content}");

            return JObject.Parse(content)["access_token"].ToString();
        }

        private string ProvisionUserInGraph(HttpClient client, string accessToken, string email, Entity contact, string domain, ITracingService tracer)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            string firstName = contact.GetAttributeValue<string>("firstname") ?? "";
            string lastName = contact.GetAttributeValue<string>("lastname") ?? "User";

            var userPayload = new
            {
                displayName = $"{firstName} {lastName}".Trim(),
                givenName = firstName,
                surname = lastName,
                mail = email,
                passwordProfile = new
                {
                    forceChangePasswordNextSignIn = false,
                    password = Guid.NewGuid().ToString("N") + "A1!"
                },
                identities = new[]
                {
                    new { signInType = "emailAddress", issuer = domain, issuerAssignedId = email }
                }
            };

            var jsonContent = new StringContent(JsonConvert.SerializeObject(userPayload), Encoding.UTF8, "application/json");
            var response = client.PostAsync("https://graph.microsoft.com/v1.0/users", jsonContent).Result;
            string responseBody = response.Content.ReadAsStringAsync().Result;

            if (response.IsSuccessStatusCode)
            {
                tracer.Trace("User created successfully.");
                return JObject.Parse(responseBody)["id"].ToString();
            }

            // Handle standard Conflict (409)
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                tracer.Trace($"Conflict: User with email {email} already exists.");
                throw new InvalidPluginExecutionException($"A user with the email address '{email}' is already registered in Entra External Id.");
            }

            // Handle BadRequest (400) that contains "already exists" or "ObjectConflict"
            if (response.StatusCode == HttpStatusCode.BadRequest && responseBody.Contains("already exists"))
            {
                tracer.Trace($"BadRequest Conflict: Object already exists for {email}. Raw response: {responseBody}");
                throw new InvalidPluginExecutionException($"A user with the email address '{email}' is already registered in Entra External Id.");
            }

            throw new Exception($"Failed to handle user in Graph: {response.StatusCode} - {responseBody}");
        }

        private void AddUserToGroup(HttpClient client, string accessToken, string userId, string groupId, ITracingService tracer)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var requestUrl = $"https://graph.microsoft.com/v1.0/groups/{groupId}/members/$ref";
            string rawPayload = "{\"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/" + userId + "\"}";
            var content = new StringContent(rawPayload, Encoding.UTF8, "application/json");

            var response = client.PostAsync(requestUrl, content).Result;
            string responseBody = response.Content.ReadAsStringAsync().Result;

            if (response.IsSuccessStatusCode)
            {
                tracer.Trace("Success: User added to security group.");
            }
            else if (response.StatusCode == HttpStatusCode.BadRequest || response.StatusCode == HttpStatusCode.Conflict)
            {
                tracer.Trace("Info: User might already be a member of the group.");
            }
            else if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                tracer.Trace($"Critical Error: 403 Forbidden. Response: {responseBody}");
                throw new Exception($"Graph API Forbidden (403): {responseBody}");
            }
            else
            {
                tracer.Trace($"Warning: Could not add user to group. Status: {response.StatusCode}. Response: {responseBody}");
            }
        }
    }
}