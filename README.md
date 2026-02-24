# Dataverse to Entra ID (CIAM) User Provisioning Plugin

Denne pluginnen automatiserer opprettelsen av brukere i **Microsoft Entra External ID (CIAM)** når en kontakt oppdateres eller opprettes i Dataverse. Den er utviklet for å være miljøuavhengig og sikker ved bruk av *Dataverse Secure Configuration*.

---

## 🚀 Funksjonalitet

* **Miljøuavhengig:** All konfigurasjon styres via Secure Configuration (ingen hardkoding).
* **Universal Domene-støtte:** Bruker `identities`-mapping som tillater alle e-postdomener (Gmail, Outlook, etc.).
* **Sikker:** Lagrer sensitive verdier som Client Secret i Dataverse sitt krypterte Secure Configuration-felt.
* **Robust:** Håndterer "Race Conditions" (409 Conflict) og dype rekursive kall i Dataverse.
* **Automatisert Gruppetilgang:** Kan automatisk legge brukere til i en spesifisert sikkerhetsgruppe (Security Group) for applikasjonstilgang.
* **Asynkron vennlig:** Designet for å kjøre i bakgrunnen uten å påvirke brukerens hastighet i portalen.
* **Fjernbruker-støtte:** Hvis en konfigurert boolean-felt (via unsecure config) eksplisitt settes til `false`, fjerner pluginen brukeren fra den konfigurerte gruppen og forsøker å slette brukeren fra Entra.
* **Konfigurerbar portal-flag:** Feltnavnet som indikerer om en kontakt skal være portal-aktiv kan settes i Unsecure Configuration (se Konfigurasjon).
* **PostImage-fallback og TLS:** Leser data fra `PostImage` når tilgjengelig (fallback til Target), og tvinger TLS 1.2 for Graph-kommunikasjon.

---

## 🛠 Forberedelser i Azure (CIAM)

Før pluginnen kan kommunisere med Entra ID, må du konfigurere en **App Registration**:

1.  **API Permissions:** Legg til Microsoft Graph med følgende *Application Permissions*:
    * `User.ReadWrite.All`
    * `GroupMember.ReadWrite.All` (Påkrevd for å legge brukere i grupper)
    * `Directory.ReadWrite.All`
2.  **Admin Consent:** Klikk på **"Grant admin consent for [Tenant]"**.
3.  **Credentials:** Opprett en ny **Client Secret** og ta vare på verdien.
4.  **Group ID:** Finn **Object ID** for sikkerhetsgruppen du vil legge brukere i.

---

## ⚙️ Konfigurasjon

Limes inn i feltet for **Secure Configuration** ved registrering av Step i Plugin Registration Tool:

```json
{
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "clientId": "00000000-0000-0000-0000-000000000000",
  "clientSecret": "YOUR_SECRET_VALUE",
  "tenantDomain": "YOUR_TENANT.onmicrosoft.com",
  "groupId": "OPTIONAL_SECURITY_GROUP_GUID"
}
``` 

Hvis du ønsker at pluginen skal bruke et eget boolean-felt på kontakten for å styre portal-tilgang (f.eks. `new_isEnabledForPortal`), lim inn følgende i **Unsecure Configuration** når du registerer steppet:

```json
{
  "isEnabledForPortalField": "new_isEnabledForPortal"
}
```

Når dette er konfigurert, vil en eksplisitt `false` verdi på dette feltet gjøre at pluginen:
- fjerner brukeren fra den konfigurerte sikkerhetsgruppen (hvis `groupId` er satt)
- forsøker å slette brukeren fra Entra

Hvis `isEnabledForPortalField` ikke er angitt, oppfører pluginen seg som før (opprett/oppdater bruker og legg til i gruppe ved behov).

## 📦 Installasjon og Oppsett

Følg denne guiden for å kompilere og registrere pluginnen i ditt Dataverse-miljø.

### 1. Forberedelse av DLL
Siden pluginnen bruker eksterne biblioteker (som `Newtonsoft.Json`), må disse inkluderes i pakken som lastes opp til Dataverse.
* **Alternativ A (Anbefalt):** Bruk **Dataverse Dependent Assemblies** (NuGet-pakke) for å inkludere avhengigheter direkte i løsningen.
* **Alternativ B:** Bruk **ILRepack** eller **ILMerge** for å slå sammen alle `.dll`-filer til én enkelt assembly før registrering.

### 2. Registrering i Plugin Registration Tool (PRT)
1.  Koble til ditt miljø og velg **Register New Assembly**.
2.  Velg din kompilerte `.dll`-fil og fullfør registreringen.
3.  Høyreklikk på den nye assemblyen og velg **Register New Step**.

### 3. Step-konfigurasjon
Bruk følgende innstillinger for at pluginnen skal fungere optimalt uten å låse brukergrensesnittet:

| Parameter | Verdi |
| :--- | :--- |
| **Message** | `Update` (eller `Create`) |
| **Primary Entity** | `contact` |
| **Filtering Attributes** | `emailaddress1` |
| **Event Pipeline Stage** | `PostOperation` |
| **Execution Mode** | `Asynchronous` |
| **Deployment** | `Server` |

### 4. Sikker Konfigurasjon
Lim inn din JSON-konfigurasjon i feltet **Secure Configuration**. Dette sikrer at `clientSecret` krypteres og ikke er synlig for vanlige brukere eller i vanlige løsningseksporter.

---

## 🔍 Feilsøking og Trace Logs

Hvis synkroniseringen ikke fungerer som forventet, må du aktivere og sjekke **Plug-in Trace Log** i Dataverse (Settings -> Administration -> System Settings -> Customization).

### Vanlige feilkoder og løsninger

#### 🛑 403 Forbidden
* **Årsak:** App-registreringen i Azure mangler nødvendige tillatelser.
* **Løsning:** Kontroller at `User.ReadWrite.All` og `GroupMember.ReadWrite.All` er lagt til i Microsoft Graph, og at du har klikket på **"Grant admin consent"**.

Merk: 403 kan også oppstå ved forsøk på å slette en bruker eller oppdatere gruppe-medlemskap hvis appen mangler nødvendige Directory-tillatelser. Pluginen vil logge detaljer i trace-loggen ved slike operasjoner.

#### 🛑 409 Conflict
* **Årsak:** Brukeren eksisterer allerede i Entra ID (CIAM) med denne e-posten.
* **Løsning:** Dette er håndtert i koden. Pluginnen vil automatisk forsøke å hente den eksisterende brukerens ID for å oppdatere gruppemedlemskap i stedet for å feile.

#### 🛑 401 Unauthorized
* **Årsak:** Ugyldig `clientSecret` eller `clientId`.
* **Løsning:** Dobbeltsjekk verdiene i din **Secure Configuration** JSON mot verdiene i Azure Portal. Husk at en Secret har en utløpsdato.

#### 🛑 Token Endpoint Discovery Failure
* **Årsak:** Feil `tenantId` eller `tenantDomain`.
* **Løsning:** Sørg for at `tenantDomain` er din korrekte `.onmicrosoft.com`-adresse, da denne brukes for å generere autorisasjons-URL-en.

#### 🛑 Plugin Timeout
* **Årsak:** Ofte forårsaket av dype rekursive kall eller nettverkstreghet mot Graph API.
* **Løsning:** Sørg for at pluginnen kjører **Asynchronous**. Dette gir pluginnen mer tid til å fullføre (opptil 2 minutter) uten at brukeren får feilmelding i nettleseren.

Denne pluginen håndterer også vanlige konflikt-tilfeller fra Graph (f.eks. `proxyAddresses` eller `userPrincipalName` konflikter) ved å forsøke å finne eksisterende bruker og fortsette uten å rulle tilbake CRM-operasjonen.