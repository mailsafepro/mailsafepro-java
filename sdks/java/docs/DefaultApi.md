# DefaultApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**askGeminiGeminiGet**](DefaultApi.md#askGeminiGeminiGet) | **GET** /gemini | Ask Gemini |
| [**runAuditAdminAuditProjectPost**](DefaultApi.md#runAuditAdminAuditProjectPost) | **POST** /admin/audit_project | Run Audit |


<a id="askGeminiGeminiGet"></a>
# **askGeminiGeminiGet**
> Object askGeminiGeminiGet(prompt)

Ask Gemini

Llama a Gemini para generar texto a partir de un prompt

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.DefaultApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    DefaultApi apiInstance = new DefaultApi(defaultClient);
    String prompt = "prompt_example"; // String | 
    try {
      Object result = apiInstance.askGeminiGeminiGet(prompt);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling DefaultApi#askGeminiGeminiGet");
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
| **prompt** | **String**|  | |

### Return type

**Object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **422** | Validation Error |  -  |

<a id="runAuditAdminAuditProjectPost"></a>
# **runAuditAdminAuditProjectPost**
> Object runAuditAdminAuditProjectPost(path, xAuditToken)

Run Audit

Lanza auditoría en path (ruta absoluta o relativa a la raíz del proyecto). Header obligatorio: X-Audit-Token: &lt;AUDIT_SECRET&gt;

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.DefaultApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    DefaultApi apiInstance = new DefaultApi(defaultClient);
    String path = "."; // String | 
    String xAuditToken = "xAuditToken_example"; // String | 
    try {
      Object result = apiInstance.runAuditAdminAuditProjectPost(path, xAuditToken);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling DefaultApi#runAuditAdminAuditProjectPost");
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
| **path** | **String**|  | [optional] [default to .] |
| **xAuditToken** | **String**|  | [optional] |

### Return type

**Object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **422** | Validation Error |  -  |

