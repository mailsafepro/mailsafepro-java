

# EmailResponse

Comprehensive email validation response

## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
|**email** | **String** | Validated email address |  |
|**valid** | **Boolean** | Overall validation result |  |
|**detail** | **String** | Validation details summary |  [optional] |
|**processingTime** | **BigDecimal** |  |  [optional] |
|**provider** | **String** |  |  [optional] |
|**reputation** | **BigDecimal** |  |  [optional] |
|**fingerprint** | **String** |  |  [optional] |
|**qualityScore** | **BigDecimal** |  |  [optional] |
|**riskLevel** | **RiskLevelEnum** |  |  [optional] |
|**suggestions** | **List&lt;String&gt;** | Improvement suggestions |  [optional] |
|**smtp** | [**SMTPInfo**](SMTPInfo.md) |  |  [optional] |
|**dns** | [**DNSInfo**](DNSInfo.md) |  |  [optional] |
|**riskScore** | **BigDecimal** |  |  [optional] |
|**validationTier** | **String** |  |  [optional] |
|**suggestedAction** | **String** |  |  [optional] |



