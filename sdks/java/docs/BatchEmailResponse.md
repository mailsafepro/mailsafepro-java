

# BatchEmailResponse

Batch validation response

## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
|**count** | **Integer** | Total emails processed |  |
|**validCount** | **Integer** | Number of valid emails |  |
|**invalidCount** | **Integer** | Number of invalid emails |  |
|**processingTime** | **BigDecimal** | Total processing time in seconds |  |
|**averageTime** | **BigDecimal** | Average processing time per email |  |
|**results** | [**List&lt;EmailResponse&gt;**](EmailResponse.md) | Individual validation results |  |



