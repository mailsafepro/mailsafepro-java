# WebhooksApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**createWebhookWebhooksManagementWebhooksPost**](WebhooksApi.md#createWebhookWebhooksManagementWebhooksPost) | **POST** /webhooks-management/webhooks/ | Create Webhook |
| [**deleteWebhookWebhooksManagementWebhooksWebhookIdDelete**](WebhooksApi.md#deleteWebhookWebhooksManagementWebhooksWebhookIdDelete) | **DELETE** /webhooks-management/webhooks/{webhook_id} | Delete Webhook |
| [**getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet**](WebhooksApi.md#getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet) | **GET** /webhooks-management/webhooks/{webhook_id}/deliveries | Get Deliveries |
| [**getWebhookWebhooksManagementWebhooksWebhookIdGet**](WebhooksApi.md#getWebhookWebhooksManagementWebhooksWebhookIdGet) | **GET** /webhooks-management/webhooks/{webhook_id} | Get Webhook |
| [**listWebhooksWebhooksManagementWebhooksGet**](WebhooksApi.md#listWebhooksWebhooksManagementWebhooksGet) | **GET** /webhooks-management/webhooks/ | List Webhooks |
| [**registerEndpointWebhooksV1WebhooksEndpointsRegisterPost**](WebhooksApi.md#registerEndpointWebhooksV1WebhooksEndpointsRegisterPost) | **POST** /webhooks/v1/webhooks/endpoints/register | Register Endpoint |
| [**registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0**](WebhooksApi.md#registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0) | **POST** /webhooks/v1/webhooks/endpoints/register | Register Endpoint |
| [**rotateSecretWebhooksV1WebhooksEndpointsRotatePost**](WebhooksApi.md#rotateSecretWebhooksV1WebhooksEndpointsRotatePost) | **POST** /webhooks/v1/webhooks/endpoints/rotate | Rotate Secret |
| [**rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0**](WebhooksApi.md#rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0) | **POST** /webhooks/v1/webhooks/endpoints/rotate | Rotate Secret |
| [**testWebhookWebhooksManagementWebhooksWebhookIdTestPost**](WebhooksApi.md#testWebhookWebhooksManagementWebhooksWebhookIdTestPost) | **POST** /webhooks-management/webhooks/{webhook_id}/test | Test Webhook |
| [**updateWebhookWebhooksManagementWebhooksWebhookIdPatch**](WebhooksApi.md#updateWebhookWebhooksManagementWebhooksWebhookIdPatch) | **PATCH** /webhooks-management/webhooks/{webhook_id} | Update Webhook |


<a id="createWebhookWebhooksManagementWebhooksPost"></a>
# **createWebhookWebhooksManagementWebhooksPost**
> Object createWebhookWebhooksManagementWebhooksPost(webhookCreate)

Create Webhook

Create a new webhook endpoint.  Events available: - validation.completed: Single email validation finished - batch.completed: Batch validation finished - usage.limit_reached: API usage limit reached (80%)

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    WebhookCreate webhookCreate = new WebhookCreate(); // WebhookCreate | 
    try {
      Object result = apiInstance.createWebhookWebhooksManagementWebhooksPost(webhookCreate);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#createWebhookWebhooksManagementWebhooksPost");
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
| **webhookCreate** | [**WebhookCreate**](WebhookCreate.md)|  | |

### Return type

**Object**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **422** | Validation Error |  -  |

<a id="deleteWebhookWebhooksManagementWebhooksWebhookIdDelete"></a>
# **deleteWebhookWebhooksManagementWebhooksWebhookIdDelete**
> Object deleteWebhookWebhooksManagementWebhooksWebhookIdDelete(webhookId)

Delete Webhook

Delete webhook.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    try {
      Object result = apiInstance.deleteWebhookWebhooksManagementWebhooksWebhookIdDelete(webhookId);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#deleteWebhookWebhooksManagementWebhooksWebhookIdDelete");
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
| **webhookId** | **String**|  | |

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

<a id="getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet"></a>
# **getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet**
> Object getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet(webhookId, limit)

Get Deliveries

Get delivery history for webhook.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    Integer limit = 100; // Integer | 
    try {
      Object result = apiInstance.getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet(webhookId, limit);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet");
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
| **webhookId** | **String**|  | |
| **limit** | **Integer**|  | [optional] [default to 100] |

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

<a id="getWebhookWebhooksManagementWebhooksWebhookIdGet"></a>
# **getWebhookWebhooksManagementWebhooksWebhookIdGet**
> Object getWebhookWebhooksManagementWebhooksWebhookIdGet(webhookId)

Get Webhook

Get webhook details.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    try {
      Object result = apiInstance.getWebhookWebhooksManagementWebhooksWebhookIdGet(webhookId);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#getWebhookWebhooksManagementWebhooksWebhookIdGet");
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
| **webhookId** | **String**|  | |

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

<a id="listWebhooksWebhooksManagementWebhooksGet"></a>
# **listWebhooksWebhooksManagementWebhooksGet**
> Object listWebhooksWebhooksManagementWebhooksGet()

List Webhooks

List all webhooks for authenticated user.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    try {
      Object result = apiInstance.listWebhooksWebhooksManagementWebhooksGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#listWebhooksWebhooksManagementWebhooksGet");
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

<a id="registerEndpointWebhooksV1WebhooksEndpointsRegisterPost"></a>
# **registerEndpointWebhooksV1WebhooksEndpointsRegisterPost**
> Object registerEndpointWebhooksV1WebhooksEndpointsRegisterPost(registerEndpoint, xAPIKey, authorization)

Register Endpoint

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    RegisterEndpoint registerEndpoint = new RegisterEndpoint(); // RegisterEndpoint | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.registerEndpointWebhooksV1WebhooksEndpointsRegisterPost(registerEndpoint, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#registerEndpointWebhooksV1WebhooksEndpointsRegisterPost");
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
| **registerEndpoint** | [**RegisterEndpoint**](RegisterEndpoint.md)|  | |
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

<a id="registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0"></a>
# **registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0**
> Object registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0(registerEndpoint, xAPIKey, authorization)

Register Endpoint

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    RegisterEndpoint registerEndpoint = new RegisterEndpoint(); // RegisterEndpoint | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0(registerEndpoint, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#registerEndpointWebhooksV1WebhooksEndpointsRegisterPost_0");
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
| **registerEndpoint** | [**RegisterEndpoint**](RegisterEndpoint.md)|  | |
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

<a id="rotateSecretWebhooksV1WebhooksEndpointsRotatePost"></a>
# **rotateSecretWebhooksV1WebhooksEndpointsRotatePost**
> Object rotateSecretWebhooksV1WebhooksEndpointsRotatePost(rotateSecret, xAPIKey, authorization)

Rotate Secret

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    RotateSecret rotateSecret = new RotateSecret(); // RotateSecret | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.rotateSecretWebhooksV1WebhooksEndpointsRotatePost(rotateSecret, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#rotateSecretWebhooksV1WebhooksEndpointsRotatePost");
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
| **rotateSecret** | [**RotateSecret**](RotateSecret.md)|  | |
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

<a id="rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0"></a>
# **rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0**
> Object rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0(rotateSecret, xAPIKey, authorization)

Rotate Secret

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    RotateSecret rotateSecret = new RotateSecret(); // RotateSecret | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0(rotateSecret, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#rotateSecretWebhooksV1WebhooksEndpointsRotatePost_0");
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
| **rotateSecret** | [**RotateSecret**](RotateSecret.md)|  | |
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

<a id="testWebhookWebhooksManagementWebhooksWebhookIdTestPost"></a>
# **testWebhookWebhooksManagementWebhooksWebhookIdTestPost**
> Object testWebhookWebhooksManagementWebhooksWebhookIdTestPost(webhookId)

Test Webhook

Send test event to webhook.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    try {
      Object result = apiInstance.testWebhookWebhooksManagementWebhooksWebhookIdTestPost(webhookId);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#testWebhookWebhooksManagementWebhooksWebhookIdTestPost");
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
| **webhookId** | **String**|  | |

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

<a id="updateWebhookWebhooksManagementWebhooksWebhookIdPatch"></a>
# **updateWebhookWebhooksManagementWebhooksWebhookIdPatch**
> Object updateWebhookWebhooksManagementWebhooksWebhookIdPatch(webhookId, webhookUpdate)

Update Webhook

Update webhook configuration.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.WebhooksApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksApi apiInstance = new WebhooksApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    WebhookUpdate webhookUpdate = new WebhookUpdate(); // WebhookUpdate | 
    try {
      Object result = apiInstance.updateWebhookWebhooksManagementWebhooksWebhookIdPatch(webhookId, webhookUpdate);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksApi#updateWebhookWebhooksManagementWebhooksWebhookIdPatch");
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
| **webhookId** | **String**|  | |
| **webhookUpdate** | [**WebhookUpdate**](WebhookUpdate.md)|  | |

### Return type

**Object**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **422** | Validation Error |  -  |

