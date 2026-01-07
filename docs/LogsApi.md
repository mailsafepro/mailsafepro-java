# LogsApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**clearRequestLogsLogsLogsRequestsDelete**](LogsApi.md#clearRequestLogsLogsLogsRequestsDelete) | **DELETE** /logs/logs/requests | Clear Request Logs |
| [**getRequestLogsLogsLogsRequestsGet**](LogsApi.md#getRequestLogsLogsLogsRequestsGet) | **GET** /logs/logs/requests | Get Request Logs |


<a id="clearRequestLogsLogsLogsRequestsDelete"></a>
# **clearRequestLogsLogsLogsRequestsDelete**
> Object clearRequestLogsLogsLogsRequestsDelete()

Clear Request Logs

Clear all request logs for current user.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.LogsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    LogsApi apiInstance = new LogsApi(defaultClient);
    try {
      Object result = apiInstance.clearRequestLogsLogsLogsRequestsDelete();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling LogsApi#clearRequestLogsLogsLogsRequestsDelete");
      System.err.println("Status code: " + e.getCode());
      System.err.println("Reason: " + e.getResponseBody());
      System.err.println("Response headers: " + e.getResponseHeaders());
      e.printStackTrace();
    }
  }
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**Object**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="getRequestLogsLogsLogsRequestsGet"></a>
# **getRequestLogsLogsLogsRequestsGet**
> Object getRequestLogsLogsLogsRequestsGet(limit, statusCode, endpoint, method, since)

Get Request Logs

Get request logs for authenticated user.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.LogsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    LogsApi apiInstance = new LogsApi(defaultClient);
    Integer limit = 100; // Integer | Max results to return
    Integer statusCode = 56; // Integer | Filter by HTTP status code
    String endpoint = "endpoint_example"; // String | Filter by endpoint path
    String method = "method_example"; // String | Filter by HTTP method (GET, POST, etc)
    OffsetDateTime since = OffsetDateTime.now(); // OffsetDateTime | Filter by timestamp (ISO 8601)
    try {
      Object result = apiInstance.getRequestLogsLogsLogsRequestsGet(limit, statusCode, endpoint, method, since);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling LogsApi#getRequestLogsLogsLogsRequestsGet");
      System.err.println("Status code: " + e.getCode());
      System.err.println("Reason: " + e.getResponseBody());
      System.err.println("Response headers: " + e.getResponseHeaders());
      e.printStackTrace();
    }
  }
}
```

### Parameters

| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **limit** | **Integer**| Max results to return | [optional] [default to 100] |
| **statusCode** | **Integer**| Filter by HTTP status code | [optional] |
| **endpoint** | **String**| Filter by endpoint path | [optional] |
| **method** | **String**| Filter by HTTP method (GET, POST, etc) | [optional] |
| **since** | **OffsetDateTime**| Filter by timestamp (ISO 8601) | [optional] |

### Return type

**Object**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **422** | Validation Error |  -  |

