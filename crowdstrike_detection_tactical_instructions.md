# Tactical Instructions — CrowdStrike Detection & Response Configuration

**Purpose:** Enable enhanced visibility, ingest IIS log data, build correlation-rule-based triggers, and configure automated response actions to detect and capture the malware associated with this engagement.

**Audience:** Analyst/engineer implementing this configuration in the Falcon console
**Prerequisite access:** Falcon Administrator or equivalent role with Sensor Visibility, Data Connector/Data Onboarding, Next-Gen SIEM Correlation Rules, Custom IOA, and Fusion Workflow permissions

> Note: Exact menu paths can shift slightly between Falcon console versions/tenants. Verify each step against your live console and adjust as needed — this document should be treated as a working checklist, not a guaranteed pixel-for-pixel walkthrough.

---

## Phase 1 — Enable Enhanced Sensor Visibility

**1.1 Enable Enhanced DLL Load Visibility**
1. Navigate to **Endpoint Security → Configuration → Sensor Visibility Exclusions** (or **Prevention Policies**, depending on console version — this setting is typically part of the Sensor Visibility policy attached to the host group).
2. Locate the policy applied to the target host group (SharePoint WFE/App servers).
3. Enable **Enhanced DLL Load Visibility** (increases telemetry on module/DLL loads across monitored processes).
4. Save and apply the policy to the correct host group.

**1.2 Enable Script-Based Execution Visibility (Script-Based Execution Monitoring)**
1. Same policy location as above (Sensor Visibility / Prevention Policy settings).
2. Enable **Script-Based Execution Monitoring** (increases visibility into PowerShell, WMI, and other script-based execution activity).
3. Save and apply to the correct host group.

**1.3 Validate**
- Confirm policy assignment against the correct host group (double-check this targets the SharePoint WFE and Application server roles specifically, not a broader/incorrect group).
- Confirm via a test event (e.g., a benign PowerShell execution) that expanded telemetry is now appearing in Falcon's event data before relying on it.

---

## Phase 2 — Add IIS Log Data Stream

**2.1 Prerequisites**
- Confirm your Falcon subscription includes **Next-Gen SIEM** (data connector/data onboarding capability) — this is required for custom log ingestion.
- Confirm you have **Administrator or Connector Manager** access in the Falcon console.

**2.2 Create the data connector**
1. In the Falcon console, go to **Next-Gen SIEM → Data ingestion → Data connectors** (may also appear as **Data Onboarding**).
2. Click **Add data connector**.
3. Select the **HEC/HTTP Event Data Connector** (this is the general-purpose connector used to ingest custom log sources like IIS logs, as opposed to a pre-built vendor-specific connector).
4. In the **New connection** dialog, review connector metadata and click **Configure**.
5. Provide:
   - **Connector name** (e.g., `SharePoint-IIS-Logs`)
   - **Description** (optional)
   - **Parser** — select an existing IIS/W3C log parser if available, or create a custom parser matching your IIS log format (W3C extended log format field order/fields in use on the source servers).
6. Accept the Terms and Conditions.
7. Click **Save**.

**2.3 Generate the API key**
1. Once saved, return to **Data Connectors → Data Connections**.
2. Click the menu (⋮) next to the newly created connector.
3. Select **Generate API key**.
4. **Copy and securely store the API Key and API URL immediately** — this value is displayed only once.

**2.4 Configure the log shipper**
1. Deploy a log shipper on/near the IIS log source (CrowdStrike recommends the **Falcon LogScale Collector**) on the SharePoint WFE/App servers or a centralized log aggregation point.
2. Configure the shipper to read IIS W3C logs (typically `%SystemDrive%\inetpub\logs\LogFiles\`) and forward to the HEC endpoint:
   ```yaml
   sources:
     iis_logs:
       type: file
       path: "C:\\inetpub\\logs\\LogFiles\\**\\*.log"
   sinks:
     ngsiem:
       type: hec
       token: <API_key_generated_in_step_2.3>
       url: <API_URL_generated_in_step_2.3>
   ```
   (Adjust source path/type to match your actual shipper configuration and IIS log location.)

**2.5 Verify ingestion**
1. Wait at least 15 minutes after configuration before checking.
2. Return to **Data Connectors → Data Connections**, confirm **Status = Active**.
3. Click the menu (⋮) → **Show events** to confirm IIS log data is arriving and fields are parsing correctly (especially the `Cs-cookie`/cookie field and `cs-uri-stem` field you'll need for correlation rules in Phase 3).

---

## Phase 3 — Build LogScale Correlation Rules (Triggers)

All four rules below should be created under **Next-Gen SIEM → Correlation Rules** (or **Custom Detections**, depending on console labeling). Insert your validated LogScale query syntax into each.

**3.1 Watchlist-based IIS rule (known IPs / known pages)**
- **Purpose:** Alert when IIS logs show activity from a known-bad IP or against a known-targeted page, using a maintained watchlist variable.
- **Implementation:** Define your watchlist (IPs, target URI patterns) as a LogScale array/variable referenced in the query.
- **Query:**
  ```
  [INSERT VALIDATED LOGSCALE QUERY — watchlist-based IP/URI match]
  ```
- **Action on match:** Trigger response workflow (see Phase 4).

**3.2 .NET assembly load hunting query**
- **Purpose:** Detect load events associated with the specific known-malicious .NET assembly/module names identified in this investigation.
- **Query:**
  ```
  [INSERT VALIDATED LOGSCALE QUERY — .NET assembly/module load match]
  ```
- **Action on match:** Trigger response workflow (see Phase 4).

**3.3 Machine-key-stealing DLL file write detection**
- **Purpose:** Detect the specific file write event associated with the known machine-key-theft DLL.
- **Query:**
  ```
  [INSERT VALIDATED LOGSCALE QUERY — known machine-key-theft DLL file write]
  ```
- **Action on match:** Trigger response workflow (see Phase 4).

**3.4 Gzip file write detection**
- **Purpose:** Detect file write events matching the known gzip file pattern/destination used by the threat actor.
- **Query:**
  ```
  [INSERT VALIDATED LOGSCALE QUERY — gzip file write to known destination]
  ```
- **Action on match:** Trigger response workflow (see Phase 4).

**3.5 Validate each rule independently**
- Test each correlation rule against historical/known-good data before enabling live, to confirm correct field mapping and no unintended false positives.
- Confirm each rule is capable of serving as a Fusion workflow trigger event (correlation rule match → detection → Fusion trigger).

---

## Phase 4 — Automated Response Workflow (Falcon Fusion SOAR)

**4.1 Workflow trigger**
- **Trigger event:** Detection created, filtered to match any of the four correlation rules from Phase 3 (via rule name/ID condition).

**4.2 Response action sequence**
1. **RTR — Execute custom PowerShell script (Move File action)**
   - Custom RTR script that:
     - Copies the target dump output to a separate, non-default location on the host (e.g., moving from its default working directory to a staging path) to reduce risk of the file being altered/deleted before retrieval.
   - Stage this script via **Configuration → Response Scripts** ahead of time so it's available to the Fusion workflow as a callable action.
2. **RTR — Process memory dump**
   - Execute `memdump <PID> <output_name>` against the process identified by the triggering detection (pass PID dynamically from the detection event context).
3. **RTR — Get File**
   - Retrieve the moved/staged dump file from the host into the Falcon file vault.
4. **RTR — Execute custom PowerShell script (Delete File action)**
   - Remove the staged dump file from the host filesystem after successful retrieval, to avoid leaving forensic artifacts sitting on a system the TA may still have access to.
5. **Notification**
   - Send alert to analyst distribution (email/Slack/Teams/ticketing integration) confirming trigger fired, dump retrieved, and file cleanup completed.

**4.3 Sequencing/dependency notes**
- Ensure each action in the Fusion workflow is configured to run **sequentially with dependency on prior step success** (Move → Dump → Get → Delete), not in parallel, to avoid retrieving/deleting a file before it's fully written.
- Add a reasonable wait/retry condition between the memory dump action and the Get File action if dump completion time may exceed default step timing.

**4.4 Testing**
- Validate the full chain (trigger → move script → memdump → get file → delete script) against a controlled, benign test scenario in a test environment before relying on it against live detections.
- Confirm retrieved files land correctly in the Falcon file vault and are subsequently copied to your team's secure evidence storage location as part of standard evidence handling.

---

## Phase 5 — Documentation & Sign-off

- [ ] Document final LogScale query text for all four correlation rules (for case record and reproducibility)
- [ ] Document Fusion workflow configuration (trigger conditions, action sequence, script names/IDs used)
- [ ] Confirm host group scoping is correct for all policies/rules/workflows (target only the intended SharePoint WFE/App servers)
- [ ] Obtain sign-off from customer/stakeholders on enabling this configuration in their environment, including disclosure of any custom scripts (Move File, Delete File) being deployed
- [ ] Record testing results and known limitations before go-live
