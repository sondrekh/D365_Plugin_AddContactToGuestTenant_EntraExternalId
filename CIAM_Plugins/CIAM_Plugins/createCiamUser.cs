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
    /// when a Contact is created or updated in Dataverse.
    /// </summary>
    public class CreateCiamUser : IPlugin
    {
        private readonly string _secureConfig;

        // The constructor accepts the secure configuration string from the Plugin Step registration
        public CreateCiamUser(string unsecureConfig, string secureConfig)
        {
            _secureConfig = secureConfig;
        }

        public void Execute(IServiceProvider serviceProvider)
        {
            ITracingService tracer = (ITracingService)serviceProvider.GetService(typeof(ITracingService));
            IPluginExecutionContext context = (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));
            IOrganizationServiceFactory serviceFactory = (IOrganizationServiceFactory)serviceProvider.GetService(typeof(IOrganizationServiceFactory));

            // Logic to prevent infinite loops (depth check)
            if (context.Depth > 2)
            {
                tracer.Trace("Context Depth > 2. Execution halted to prevent potential infinite loop.");
                return;
            }

            if (string.IsNullOrEmpty(_secureConfig))
            {
                tracer.Trace("Critical: Secure Configuration is missing. Please provide JSON config in the Plugin Step.");
                return;
            }

            // Verify that we have a Target entity
            if (!context.InputParameters.Contains("Target") || !(context.InputParameters["Target"] is Entity targetEntity))
                return;

            // Use Post-Image if available to get full contact data, otherwise use Target
            Entity contact = context.PostEntityImages.Contains("PostImage") 
                ? context.PostEntityImages["PostImage"] 
                : targetEntity;

            string email = contact.GetAttributeValue<string>("emailaddress1");
            if (string.IsNullOrEmpty(email))
            {
                tracer.Trace("Skipping: No email address (emailaddress1) provided for this contact.");
                return;
            }

            try
            {
                // Parse secure configuration JSON
                JObject config = JObject.Parse(_secureConfig);
                string tenantId = config["tenantId"]?.ToString();
                string clientId = config["clientId"]?.ToString();
                string clientSecret = config["clientSecret"]?.ToString();
                string domain = config["tenantDomain"]?.ToString();

                if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(domain))
                {
                    throw new InvalidPluginExecutionException("Configuration Error: Missing required fields in Secure Configuration (tenantId, clientId, clientSecret, tenantDomain).");
                }

                tracer.Trace($"Initiating CIAM provisioning for: {email} using tenant {domain}");

                // 1. Acquire Access Token from Microsoft Identity Platform
                string accessToken = GetGraphAccessToken(tenantId, clientId, clientSecret, tracer);
                tracer.Trace($"Access token successfully acquired from Microsoft Identity Platform. {accessToken}");

                // 2. Create the User in Microsoft Graph
                ProvisionUserInGraph(accessToken, email, contact, domain, tracer);
            }
            catch (Exception ex)
            {
                tracer.Trace($"Plugin Execution Failed: {ex.Message}");
                // Rethrow as a Dataverse exception to inform the user/admin
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

                if (!response.IsSuccessStatusCode)
                {
                    tracer.Trace($"OAuth2 Error Response: {content}");
                    throw new Exception("Failed to authenticate with Microsoft Graph API. Check your Client ID, Secret and Tenant ID.");
                }

                return JObject.Parse(content)["access_token"].ToString();
            }
        }

        private void ProvisionUserInGraph(string accessToken, string email, Entity contact, string domain, ITracingService tracer)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                string firstName = contact.GetAttributeValue<string>("firstname") ?? "Portal";
                string lastName = contact.GetAttributeValue<string>("lastname") ?? "User";

                // Constructing the CIAM identity payload
                var userPayload = new
                {
                    displayName = $"{firstName} {lastName}",
                    givenName = firstName,
                    surname = lastName,
                    mail = email, 
                    passwordProfile = new { 
                        forceChangePasswordNextSignIn = false, 
                        password = Guid.NewGuid().ToString("N") + "!" + Guid.NewGuid().ToString("N").Substring(0,4).ToUpper() // Random secure password
                    },
                    identities = new[]
                    {
                        new { 
                            signInType = "emailAddress", 
                            issuer = domain, // This must be the primary onmicrosoft.com domain
                            issuerAssignedId = email 
                        }
                    }
                };

                var jsonContent = new StringContent(JObject.FromObject(userPayload).ToString(), Encoding.UTF8, "application/json");
                var response = client.PostAsync("https://graph.microsoft.com/v1.0/users", jsonContent).Result;
                string responseBody = response.Content.ReadAsStringAsync().Result;

                if (response.IsSuccessStatusCode)
                {
                    tracer.Trace("Success: User account has been provisioned in Entra ID.");
                }
                else
                {
                    int statusCode = (int)response.StatusCode;

                    if (statusCode == 409) // Conflict: User already exists
                    {
                        tracer.Trace("Notification: User already exists in the destination tenant. No further action needed.");
                    }
                    else if (statusCode == 403)
                    {
                        throw new Exception("Permissions Error: The App Registration lacks 'User.ReadWrite.All' or 'Directory.ReadWrite.All' application permissions.");
                    }
                    else
                    {
                        tracer.Trace($"Graph API Error Detail: {responseBody}");
                        throw new Exception($"Microsoft Graph API error ({statusCode}): {response.ReasonPhrase}. Consult the trace log for details.");
                    }
                }
            }
        }
    }
}