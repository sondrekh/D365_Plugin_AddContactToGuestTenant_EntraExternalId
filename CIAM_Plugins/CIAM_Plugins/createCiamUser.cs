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
        private readonly string _unsecureConfig;

        public CreateCiamUser(string unsecureConfig, string secureConfig)
        {
            _unsecureConfig = unsecureConfig;
            _secureConfig = secureConfig;
        }

        private void DeleteUserFromGraph(HttpClient client, string accessToken, string email, ITracingService tracer)
        {
            try
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var safeEmail = (email ?? string.Empty).Replace("'", "''");

                // Try locating the user by mail, then otherMails, then identities
                JArray users = null;

                // Search by mail
                var mailFilterUrl = $"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{safeEmail}'&$select=id";
                var mailGet = client.GetAsync(mailFilterUrl).Result;
                if (mailGet.IsSuccessStatusCode)
                {
                    var mailResult = JObject.Parse(mailGet.Content.ReadAsStringAsync().Result);
                    users = (JArray)mailResult["value"];
                }

                // If not found, search by otherMails
                if (users == null || users.Count == 0)
                {
                    var otherMailsFilter = $"https://graph.microsoft.com/v1.0/users?$filter=otherMails/any(m:m eq '{safeEmail}')&$select=id";
                    var otherGet = client.GetAsync(otherMailsFilter).Result;
                    if (otherGet.IsSuccessStatusCode)
                    {
                        var otherResult = JObject.Parse(otherGet.Content.ReadAsStringAsync().Result);
                        users = (JArray)otherResult["value"];
                    }
                }

                // If still not found, fallback to identities lookup
                if (users == null || users.Count == 0)
                {
                    var identitiesFilterLocal = $"https://graph.microsoft.com/v1.0/users?$filter=identities/any(id:id/issuerAssignedId eq '{safeEmail}')&$select=id";
                    var idGetLocal = client.GetAsync(identitiesFilterLocal).Result;
                    if (idGetLocal.IsSuccessStatusCode)
                    {
                        var idResultLocal = JObject.Parse(idGetLocal.Content.ReadAsStringAsync().Result);
                        users = (JArray)idResultLocal["value"];
                    }
                }

                if (users == null || users.Count == 0)
                {
                    tracer.Trace($"Info: No Entra user found for {email}; nothing to delete.");
                    return;
                }

                var userId = users[0]["id"].ToString();

                // Delete the user
                var deleteUrl = $"https://graph.microsoft.com/v1.0/users/{userId}";
                var deleteResponse = client.DeleteAsync(deleteUrl).Result;

                if (deleteResponse.IsSuccessStatusCode)
                {
                    tracer.Trace($"Success: User {email} (id: {userId}) deleted from Entra.");
                }
                else if (deleteResponse.StatusCode == HttpStatusCode.NotFound)
                {
                    tracer.Trace($"Info: User {email} not found when attempting delete.");
                }
                else if (deleteResponse.StatusCode == HttpStatusCode.Forbidden)
                {
                    var responseBody = deleteResponse.Content.ReadAsStringAsync().Result;
                    tracer.Trace($"Warning: Forbidden deleting user {email}. Response: {responseBody}");
                }
                else
                {
                    var responseBody = deleteResponse.Content.ReadAsStringAsync().Result;
                    tracer.Trace($"Warning: Could not delete user {email}. Status: {deleteResponse.StatusCode}. Response: {responseBody}");
                }
            }
            catch (Exception ex)
            {
                tracer.Trace($"Warning: Exception while deleting user {email} from Entra: {ex.Message}");
            }
        }

        public void Execute(IServiceProvider serviceProvider)
        {
            ITracingService tracer = (ITracingService)serviceProvider.GetService(typeof(ITracingService));
            IPluginExecutionContext context = (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));

            // Ensure use of TLS 1.2 for communication with Microsoft Graph
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

            // Use PostImage for robust data access, fall back to Target
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

                // Read unsecure config to get the logical name of the boolean field that indicates portal enablement
                string isEnabledForPortalField = null;
                if (!string.IsNullOrEmpty(_unsecureConfig))
                {
                    try
                    {
                        var unsecure = JObject.Parse(_unsecureConfig);
                        isEnabledForPortalField = unsecure["isEnabledForPortalField"]?.ToString();
                    }
                    catch (Exception ex)
                    {
                        tracer.Trace($"Warning: Failed to parse unsecure configuration: {ex.Message}");
                    }
                }

                // Determine the contact's portal-enabled flag (if configured)
                bool? isPortalEnabled = null;
                if (!string.IsNullOrEmpty(isEnabledForPortalField))
                {
                    if (contact.Attributes.Contains(isEnabledForPortalField))
                    {
                        try
                        {
                            // CRM boolean fields are represented as bool
                            isPortalEnabled = contact.GetAttributeValue<bool?>(isEnabledForPortalField);
                        }
                        catch
                        {
                            tracer.Trace($"Warning: Attribute '{isEnabledForPortalField}' exists but could not be read as a boolean.");
                        }
                    }
                    else
                    {
                        tracer.Trace($"Info: Contact does not contain attribute '{isEnabledForPortalField}'. Proceeding with default behavior.");
                    }
                }

                if (new[] { tenantId, clientId, clientSecret, domain }.Any(string.IsNullOrEmpty))
                {
                    throw new InvalidPluginExecutionException("Configuration Error: Missing required fields in Secure Configuration.");
                }

                tracer.Trace($"Initiating CIAM provisioning for: {email}");

                using (var httpClient = new HttpClient())
                {
                    httpClient.Timeout = TimeSpan.FromSeconds(60);

                    string accessToken = GetGraphAccessToken(httpClient, tenantId, clientId, clientSecret);

                    // If the portal-enabled flag is explicitly false -> remove from group (if configured)
                    if (isPortalEnabled.HasValue && isPortalEnabled.Value == false)
                    {
                        tracer.Trace($"Portal flag is false for {email}. Ensuring user is removed from configured group (if any). ");
                        if (!string.IsNullOrEmpty(groupId))
                        {
                            RemoveUserFromGroup(httpClient, accessToken, email, groupId, tracer);
                            // Also attempt to delete the user from Entra entirely
                            DeleteUserFromGraph(httpClient, accessToken, email, tracer);
                        }
                    }
                    else
                    {
                        // Default or explicit true: create user or fetch existing and add to group if configured
                        string userId = ProvisionUserInGraph(httpClient, accessToken, email, contact, domain, tracer);

                        if (!string.IsNullOrEmpty(groupId) && !string.IsNullOrEmpty(userId))
                        {
                            AddUserToGroup(httpClient, accessToken, userId, groupId, tracer);
                        }
                    }
                }
            }
            catch (InvalidPluginExecutionException ex)
            {
                // Rethrow to ensure the UI catches explicit errors
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

            // Escape single quotes in email when used in OData filters
            string safeEmail = (email ?? string.Empty).Replace("'", "''");

            // Microsoft Graph requires givenName and surname (1-64 characters)
            string firstName = contact.GetAttributeValue<string>("firstname");
            string lastName = contact.GetAttributeValue<string>("lastname");

            // Fallback logic for missing names to avoid BadRequest
            if (string.IsNullOrWhiteSpace(firstName))
            {
                firstName = email.Split('@')[0];
                if (firstName.Length > 64) firstName = firstName.Substring(0, 64);
            }

            if (string.IsNullOrWhiteSpace(lastName))
            {
                lastName = "User";
            }

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

            // Specific handling for proxyAddresses conflict: log a warning and allow save to continue
            // (This should not throw an error that rolls back the CRM operation)
            if (response.StatusCode == HttpStatusCode.BadRequest &&
                (responseBody.Contains("proxyAddresses") || responseBody.Contains("Another object with the same value for property proxyAddresses")))
            {
                tracer.Trace($"Warning: Proxy address conflict detected for {email}. Details: {responseBody}");

                // Try to locate existing user by the 'mail' property first, then otherMails, then identities
                try
                {
                    // Search by mail
                    var mailFilterUrl = $"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{safeEmail}'&$select=id";
                    var mailGet = client.GetAsync(mailFilterUrl).Result;
                    if (mailGet.IsSuccessStatusCode)
                    {
                        var mailResult = JObject.Parse(mailGet.Content.ReadAsStringAsync().Result);
                        var mailUsers = (JArray)mailResult["value"];
                        if (mailUsers != null && mailUsers.Count > 0)
                        {
                            return mailUsers[0]["id"].ToString();
                        }
                    }

                    // Search by otherMails
                    var otherMailsFilter = $"https://graph.microsoft.com/v1.0/users?$filter=otherMails/any(m:m eq '{safeEmail}')&$select=id";
                    var otherGet = client.GetAsync(otherMailsFilter).Result;
                    if (otherGet.IsSuccessStatusCode)
                    {
                        var otherResult = JObject.Parse(otherGet.Content.ReadAsStringAsync().Result);
                        var otherUsers = (JArray)otherResult["value"];
                        if (otherUsers != null && otherUsers.Count > 0)
                        {
                            return otherUsers[0]["id"].ToString();
                        }
                    }

                    // Fallback: try identities filter (email identity)
                    var identitiesFilterLocal = $"https://graph.microsoft.com/v1.0/users?$filter=identities/any(id:id/issuerAssignedId eq '{safeEmail}')&$select=id";
                    var idGetLocal = client.GetAsync(identitiesFilterLocal).Result;
                    if (idGetLocal.IsSuccessStatusCode)
                    {
                        var idResultLocal = JObject.Parse(idGetLocal.Content.ReadAsStringAsync().Result);
                        var idUsersLocal = (JArray)idResultLocal["value"];
                        if (idUsersLocal != null && idUsersLocal.Count > 0)
                        {
                            return idUsersLocal[0]["id"].ToString();
                        }
                    }
                }
                catch (Exception ex)
                {
                    tracer.Trace($"Warning: Exception while searching for existing user after proxyAddresses conflict: {ex.Message}");
                }

                // If nothing found, log and allow save to continue without throwing
                tracer.Trace($"Info: Could not locate existing user for {email} after proxyAddresses conflict. Details: {responseBody}");
                return null;
            }

            // Specific handling for userPrincipalName conflict: attempt to locate existing user and continue
            if (response.StatusCode == HttpStatusCode.BadRequest &&
                (responseBody.Contains("userPrincipalName") || responseBody.Contains("Another object with the same value for property userPrincipalName")))
            {
                tracer.Trace($"Warning: userPrincipalName conflict detected for {email}. Attempting to locate existing user. Details: {responseBody}");

                // Try finding by userPrincipalName (escape quotes)
                var upnFilterUrl = $"https://graph.microsoft.com/v1.0/users?$filter=userPrincipalName eq '{safeEmail}'&$select=id";
                var upnGet = client.GetAsync(upnFilterUrl).Result;
                if (upnGet.IsSuccessStatusCode)
                {
                    var upnResult = JObject.Parse(upnGet.Content.ReadAsStringAsync().Result);
                    var upnUsers = (JArray)upnResult["value"];
                    if (upnUsers != null && upnUsers.Count > 0)
                    {
                        return upnUsers[0]["id"].ToString();
                    }
                }

                // Fallback: try identities filter (email identity)
                var identitiesFilter = $"https://graph.microsoft.com/v1.0/users?$filter=identities/any(id:id/issuerAssignedId eq '{safeEmail}')&$select=id";
                var idGet = client.GetAsync(identitiesFilter).Result;
                if (idGet.IsSuccessStatusCode)
                {
                    var idResult = JObject.Parse(idGet.Content.ReadAsStringAsync().Result);
                    var idUsers = (JArray)idResult["value"];
                    if (idUsers != null && idUsers.Count > 0)
                    {
                        return idUsers[0]["id"].ToString();
                    }
                }

                // If nothing found, log and allow save to continue without throwing
                tracer.Trace($"Info: Could not locate existing user for {email} after userPrincipalName conflict. Details: {responseBody}");
                return null;
            }

            // Handle cases where the user already exists
            // 409 Conflict: Standard response for duplicates
            // 400 BadRequest: Happens in CIAM when proxyAddresses or identities conflict
            if (response.StatusCode == HttpStatusCode.Conflict ||
               (response.StatusCode == HttpStatusCode.BadRequest && responseBody.Contains("already exists")))
            {
                tracer.Trace($"User {email} already exists or has a conflict. Fetching existing ID.");

                // Fetch existing user ID via filter to continue the process
                var filterUrl = $"https://graph.microsoft.com/v1.0/users?$filter=identities/any(id:id/issuerAssignedId eq '{safeEmail}')&$select=id";
                var getResponse = client.GetAsync(filterUrl).Result;

                if (getResponse.IsSuccessStatusCode)
                {
                    var searchResult = JObject.Parse(getResponse.Content.ReadAsStringAsync().Result);
                    var users = (JArray)searchResult["value"];
                    if (users.Count > 0) return users[0]["id"].ToString();
                }
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

        private void RemoveUserFromGroup(HttpClient client, string accessToken, string email, string groupId, ITracingService tracer)
        {
            try
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                // Escape single quotes in email when used in OData filters
                var safeEmail = (email ?? string.Empty).Replace("'", "''");

                // Try locating the user by mail, then otherMails, then identities
                JArray users = null;

                // Search by mail
                var mailFilterUrl = $"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{safeEmail}'&$select=id";
                var mailGet = client.GetAsync(mailFilterUrl).Result;
                if (mailGet.IsSuccessStatusCode)
                {
                    var mailResult = JObject.Parse(mailGet.Content.ReadAsStringAsync().Result);
                    users = (JArray)mailResult["value"];
                }

                // If not found, search by otherMails
                if (users == null || users.Count == 0)
                {
                    var otherMailsFilter = $"https://graph.microsoft.com/v1.0/users?$filter=otherMails/any(m:m eq '{safeEmail}')&$select=id";
                    var otherGet = client.GetAsync(otherMailsFilter).Result;
                    if (otherGet.IsSuccessStatusCode)
                    {
                        var otherResult = JObject.Parse(otherGet.Content.ReadAsStringAsync().Result);
                        users = (JArray)otherResult["value"];
                    }
                }

                // If still not found, fallback to identities lookup
                if (users == null || users.Count == 0)
                {
                    var identitiesFilterLocal = $"https://graph.microsoft.com/v1.0/users?$filter=identities/any(id:id/issuerAssignedId eq '{safeEmail}')&$select=id";
                    var idGetLocal = client.GetAsync(identitiesFilterLocal).Result;
                    if (idGetLocal.IsSuccessStatusCode)
                    {
                        var idResultLocal = JObject.Parse(idGetLocal.Content.ReadAsStringAsync().Result);
                        users = (JArray)idResultLocal["value"];
                    }
                }

                if (users == null || users.Count == 0)
                {
                    tracer.Trace($"Info: No Entra user found for {email}; nothing to remove from group.");
                    return;
                }

                var userId = users[0]["id"].ToString();

                var requestUrl = $"https://graph.microsoft.com/v1.0/groups/{groupId}/members/{userId}/$ref";
                var response = client.DeleteAsync(requestUrl).Result;

                if (response.IsSuccessStatusCode)
                {
                    tracer.Trace($"Success: User {email} removed from group {groupId}.");
                }
                else if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    tracer.Trace($"Info: User {email} is not a member of group {groupId}.");
                }
                else
                {
                    var responseBody = response.Content.ReadAsStringAsync().Result;
                    tracer.Trace($"Warning: Could not remove user {email} from group. Status: {response.StatusCode}. Response: {responseBody}");
                }
            }
            catch (Exception ex)
            {
                // Do not let removal errors abort the plugin; log and continue
                tracer.Trace($"Warning: Exception while removing user {email} from group {groupId}: {ex.Message}");
            }
        }
    }
}