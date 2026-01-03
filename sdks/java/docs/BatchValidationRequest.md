

# BatchValidationRequest

Request model for batch email validation

## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
|**emails** | **List&lt;String&gt;** | List of email addresses to validate (can include invalid formats) |  |
|**checkSmtp** | **Boolean** | Perform SMTP verification for all emails |  [optional] |
|**includeRawDns** | **Boolean** | Include raw DNS records in responses |  [optional] |
|**batchSize** | **Integer** | Number of emails to process in each batch |  [optional] |
|**concurrentRequests** | **Integer** | Maximum concurrent validation requests |  [optional] |



