Dataverse to Entra ID (CIAM) User Provisioning Plugin

Denne pluginnen automatiserer opprettelsen av brukere i Microsoft Entra External ID (CIAM) når en kontakt oppdateres eller opprettes i Dataverse. Den er utviklet for å være miljøuavhengig og sikker ved bruk av Dataverse Secure Configuration.

🚀 Funksjonalitet

Miljøuavhengig: All konfigurasjon styres via Secure Configuration (ingen hardkoding).

Universal Domene-støtte: Bruker identities-mapping som tillater alle e-postdomener (Gmail, Outlook, etc.).

Sikker: Lagrer sensitive verdier som Client Secret i Dataverse sitt krypterte Secure Configuration-felt.

Robust: Håndterer "Race Conditions" (409 Conflict) og dype rekursive kall i Dataverse.

Asynkron vennlig: Designet for å kjøre i bakgrunnen uten å påvirke brukerens hastighet i portalen.

🛠 Forberedelser i Azure (CIAM)

Før pluginnen kan kommunisere med Entra ID, må du konfigurere en App Registration:

API Permissions: Legg til Microsoft Graph med følgende Application Permissions:

User.ReadWrite.All

Directory.ReadWrite.All

Admin Consent: Klikk på "Grant admin consent for [Tenant]".

Credentials: Opprett en ny Client Secret og ta vare på verdien.

⚙️ Konfigurasjon

Limes inn i feltet for Secure Configuration ved registrering av Step i Plugin Registration Tool:

{
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "clientId": "00000000-0000-0000-0000-000000000000",
  "clientSecret": "YOUR_SECRET_VALUE",
  "tenantDomain": "YOUR_TENANT.onmicrosoft.com"
}


Felt

Beskrivelse

tenantId

ID-en til din CIAM-tenant (Directory ID).

clientId

Application ID for din App Registration.

clientSecret

Hemmeligheten generert i Azure.

tenantDomain

Primær-domenet til tenanten (viktig for "Issuer"-validering).

📦 Installasjon

Bygg prosjektet: Kompiler C#-koden til en .dll-fil. Sørg for at Newtonsoft.Json er inkludert/merget (ILRepack anbefales hvis du ikke bruker Dataverse Dependent Assemblies).

Plugin Registration Tool:

Registrer Assembly.

Legg til et New Step på entiteten contact.

Message: Update (Filtrer på emailaddress1).

Stage: PostOperation.

Execution Mode: Asynchronous.

Secure Configuration: Lim inn JSON-koden over.

🔍 Feilsøking

Sjekk Plug-in Trace Log i Dataverse for detaljerte feilmeldinger:

409 Conflict: Brukeren finnes allerede i Entra ID. Pluginnen logger dette og stopper uten feil.

403 Forbidden: App-registreringen mangler rettigheter i Azure. Kontroller "Admin Consent".

Issuer Error: tenantDomain i konfigurasjonen samsvarer ikke med domenet i Azure.