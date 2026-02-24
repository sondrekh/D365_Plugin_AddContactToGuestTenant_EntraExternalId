using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Xrm.Sdk;
using Newtonsoft.Json.Linq;

namespace CIAMPlugins
{
    /// <summary>
    /// Plugin to automatically provision users in Microsoft Entra External ID (CIAM)
    /// and add them to a security group for application access.
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
            IOrganizationServiceFactory serviceFactory = (IOrganizationServiceFactory)serviceProvider.GetService(typeof(IOrganizationServiceFactory));

            if (context.Depth > 2) return;

            if (string.IsNullOrEmpty(_secureConfig))
            {
                tracer.Trace("Critical: Secure Configuration is missing.");
                return;
            }

            if (!context.InputParameters.Contains("Target") || !(context.InputParameters["Target"] is Entity targetEntity))
                return;

            Entity contact = context.PostEntityImages.Contains("PostImage") 
                ? context.PostEntityImages["PostImage"] 
                : targetEntity;

            string email = contact.GetAttributeValue<string>("emailaddress1");
            if (string.IsNullOrEmpty(email)) return;

            try
            {
                JObject config = JObject.Parse(_secureConfig);
                string tenantId = config["tenantId"]?.ToString();
                string clientId = config["clientId"]?.ToString();
                string clientSecret = config["clientSecret"]?.ToString();
                string domain = config["tenantDomain"]?.ToString();
                string groupId = config["groupId"]?.ToString(); // ID for security group

                if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(domain))
                {
                    throw new InvalidPluginExecutionException("Configuration Error: Missing required fields in Secure Configuration.");
                }

                tracer.Trace($"Initiating CIAM provisioning for: {email}");

                string accessToken = GetGraphAccessToken(tenantId, clientId, clientSecret, tracer);

                // 1. Provision the user
                string userId = ProvisionUserInGraph(accessToken, email, contact, domain, tracer);

                // 2. Add user to group if groupId is provided
                if (!string.IsNullOrEmpty(groupId) && !string.IsNullOrEmpty(userId))
                {
                    AddUserToGroup(accessToken, userId, groupId, tracer);
                }
            }
            catch (Exception ex)
            {
                tracer.Trace($"Plugin Execution Failed: {ex.Message}");
                throw new InvalidPluginExecutionException($"CIAM User Provisioning Error: {ex.Message}", ex);
            }
        }

        private string GetGraphAccessToken(string tenantId, string clientId, string clientSecret, ITracingService tracer)
        {
            using (var client = new HttpClient())
            {
                var tokenUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
                var requestBody = $"client_id={clientId}&scope=https://graph.microsoft.com/.default&client_secret={clientSecret}&grant_type=client_credentials";
                
                var response = client.PostAsync(tokenUrl, new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded")).Result;
                var content = response.Content.ReadAsStringAsync().Result;

                if (!response.IsSuccessStatusCode) throw new Exception("Graph Authentication failed.");
                return JObject.Parse(content)["access_token"].ToString();
            }
        }

        private string ProvisionUserInGraph(string accessToken, string email, Entity contact, string domain, ITracingService tracer)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var userPayload = new
                {
                    displayName = $"{contact.GetAttributeValue<string>("firstname")} {contact.GetAttributeValue<string>("lastname")}",
                    givenName = contact.GetAttributeValue<string>("firstname"),
                    surname = contact.GetAttributeValue<string>("lastname"),
                    mail = email,
                    passwordProfile = new { forceChangePasswordNextSignIn = false, password = Guid.NewGuid().ToString("N") + "A1!" },
                    identities = new[] { new { signInType = "emailAddress", issuer = domain, issuerAssignedId = email } }
                };

                var response = client.PostAsync("https://graph.microsoft.com/v1.0/users", new StringContent(JObject.FromObject(userPayload).ToString(), Encoding.UTF8, "application/json")).Result;
                string responseBody = response.Content.ReadAsStringAsync().Result;

                if (response.IsSuccessStatusCode)
                {
                    return JObject.Parse(responseBody)["id"].ToString();
                }
                
                if ((int)response.StatusCode == 409) // Conflict - user exists
                {
                    tracer.Trace("User exists. Fetching existing User ID.");
                    var getResponse = client.GetAsync($"https://graph.microsoft.com/v1.0/users/{email}").Result;
                    if (getResponse.IsSuccessStatusCode) return JObject.Parse(getResponse.Content.ReadAsStringAsync().Result)["id"].ToString();
                }

                throw new Exception($"Graph User Creation Error: {response.StatusCode}");
            }
        }

        private void AddUserToGroup(string accessToken, string userId, string groupId, ITracingService tracer)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var memberPayload = new { odataId = $"https://graph.microsoft.com/v1.0/directoryObjects/{userId}" };
                var jsonContent = new StringContent(JObject.FromObject(memberPayload).ToString(Formatting.None), Encoding.UTF8, "application/json");
                
                // Using @odata.id convention for adding members
                var request = new HttpRequestMessage(HttpMethod.Post, $"https://graph.microsoft.com/v1.0/groups/{groupId}/members/$ref");
                request.Content = new StringContent("{\"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/" + userId + "\"}", Encoding.UTF8, "application/json");

                var response = client.SendAsync(request).Result;

                if (response.IsSuccessStatusCode)
                    tracer.Trace("Success: User added to security group.");
                else if ((int)response.StatusCode == 400 || (int)response.StatusCode == 409)
                    tracer.Trace("Info: User might already be a member of the group.");
                else
                    tracer.Trace($"Warning: Could not add user to group. Status: {response.StatusCode}");
            }
        }
    }
}