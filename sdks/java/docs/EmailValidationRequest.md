

# EmailValidationRequest

Request model for single email validation

## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
|**email** | **String** | Email address to validate (RFC 5321 compliant) |  |
|**checkSmtp** | **Boolean** | Enable SMTP mailbox verification |  [optional] |
|**includeRawDns** | **Boolean** | Include raw DNS records |  [optional] |
|**testingMode** | **Boolean** | Enable testing mode (allows special TLDs like .test, .example, etc.) |  [optional] |
|**priority** | **PriorityEnum** | Validation priority level |  [optional] |



