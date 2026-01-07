# EmailValidationApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**batchValidateEmailsValidateBatchPost**](EmailValidationApi.md#batchValidateEmailsValidateBatchPost) | **POST** /validate/batch | Batch Email Validation |
| [**batchValidateUploadValidateBatchUploadPost**](EmailValidationApi.md#batchValidateUploadValidateBatchUploadPost) | **POST** /validate/batch/upload | Batch Email Validation via File Upload |
| [**getCacheStatsValidateStatsCacheGet**](EmailValidationApi.md#getCacheStatsValidateStatsCacheGet) | **GET** /validate/stats/cache | Get Cache Stats |
| [**getUsageStatsValidateStatsUsageGet**](EmailValidationApi.md#getUsageStatsValidateStatsUsageGet) | **GET** /validate/stats/usage | Get Usage Stats |
| [**healthCheckValidateHealthGet**](EmailValidationApi.md#healthCheckValidateHealthGet) | **GET** /validate/health | Health Check |
| [**healthCheckValidateHealthHead**](EmailValidationApi.md#healthCheckValidateHealthHead) | **HEAD** /validate/health | Health Check |
| [**validateEmailEndpointValidateEmailPost**](EmailValidationApi.md#validateEmailEndpointValidateEmailPost) | **POST** /validate/email | Validate Email Endpoint |


<a id="batchValidateEmailsValidateBatchPost"></a>
# **batchValidateEmailsValidateBatchPost**
> BatchEmailResponse batchValidateEmailsValidateBatchPost(batchValidationRequest, xAPIKey, authorization)

Batch Email Validation

Valida múltiples direcciones de email en una sola solicitud.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    BatchValidationRequest batchValidationRequest = new BatchValidationRequest(); // BatchValidationRequest | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      BatchEmailResponse result = apiInstance.batchValidateEmailsValidateBatchPost(batchValidationRequest, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#batchValidateEmailsValidateBatchPost");
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
| **batchValidationRequest** | [**BatchValidationRequest**](BatchValidationRequest.md)|  | |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**BatchEmailResponse**](BatchEmailResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Batch validation completed |  -  |
| **400** | Invalid batch request |  -  |
| **413** | Batch too large |  -  |
| **429** | Rate limit exceeded |  -  |
| **422** | Validation Error |  -  |

<a id="batchValidateUploadValidateBatchUploadPost"></a>
# **batchValidateUploadValidateBatchUploadPost**
> Object batchValidateUploadValidateBatchUploadPost(_file, xAPIKey, authorization, column, includeRawDns, checkSmtp)

Batch Email Validation via File Upload

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    File _file = new File("/path/to/file"); // File | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    String column = "column_example"; // String | 
    Boolean includeRawDns = false; // Boolean | 
    Boolean checkSmtp = false; // Boolean | 
    try {
      Object result = apiInstance.batchValidateUploadValidateBatchUploadPost(_file, xAPIKey, authorization, column, includeRawDns, checkSmtp);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#batchValidateUploadValidateBatchUploadPost");
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
| **_file** | **File**|  | |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |
| **column** | **String**|  | [optional] |
| **includeRawDns** | **Boolean**|  | [optional] [default to false] |
| **checkSmtp** | **Boolean**|  | [optional] [default to false] |

### Return type

**Object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: multipart/form-data
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Validation completed |  -  |
| **400** | Invalid file or parameters |  -  |
| **413** | File too large |  -  |
| **415** | Unsupported file type |  -  |
| **429** | Rate limit exceeded |  -  |
| **422** | Validation Error |  -  |

<a id="getCacheStatsValidateStatsCacheGet"></a>
# **getCacheStatsValidateStatsCacheGet**
> Object getCacheStatsValidateStatsCacheGet()

Get Cache Stats

Obtiene estadísticas de cache del sistema.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    try {
      Object result = apiInstance.getCacheStatsValidateStatsCacheGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#getCacheStatsValidateStatsCacheGet");
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

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="getUsageStatsValidateStatsUsageGet"></a>
# **getUsageStatsValidateStatsUsageGet**
> Object getUsageStatsValidateStatsUsageGet(xAPIKey, authorization)

Get Usage Stats

Obtiene estadísticas de uso del cliente actual.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.getUsageStatsValidateStatsUsageGet(xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#getUsageStatsValidateStatsUsageGet");
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
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

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

<a id="healthCheckValidateHealthGet"></a>
# **healthCheckValidateHealthGet**
> Object healthCheckValidateHealthGet()

Health Check

Health check completo del servicio de validación.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    try {
      Object result = apiInstance.healthCheckValidateHealthGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#healthCheckValidateHealthGet");
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

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="healthCheckValidateHealthHead"></a>
# **healthCheckValidateHealthHead**
> Object healthCheckValidateHealthHead()

Health Check

Health check completo del servicio de validación.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    try {
      Object result = apiInstance.healthCheckValidateHealthHead();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#healthCheckValidateHealthHead");
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

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="validateEmailEndpointValidateEmailPost"></a>
# **validateEmailEndpointValidateEmailPost**
> Object validateEmailEndpointValidateEmailPost(emailValidationRequest, xAPIKey, authorization)

Validate Email Endpoint

✅ Endpoint de validación de email con timeout y fallback robusto.  Cambios principales: - Timeout explícito por plan (FREE: 15s, PREMIUM: 45s, ENTERPRISE: 60s) - Fallback BASIC seguro si se vence - SIEMPRE retorna JSONResponse válida - client_plan en TODAS las respuestas - spam_trap_check ejecutado ANTES del timeout para estar disponible en fallback - Manejo de errores con ResponseBuilder - ✅ NUEVO: Soporte para TLD .test en testing_mode

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.EmailValidationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    EmailValidationApi apiInstance = new EmailValidationApi(defaultClient);
    EmailValidationRequest emailValidationRequest = new EmailValidationRequest(); // EmailValidationRequest | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.validateEmailEndpointValidateEmailPost(emailValidationRequest, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling EmailValidationApi#validateEmailEndpointValidateEmailPost");
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
| **emailValidationRequest** | [**EmailValidationRequest**](EmailValidationRequest.md)|  | |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

**Object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **422** | Validation Error |  -  |

