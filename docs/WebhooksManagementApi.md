# WebhooksManagementApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**createWebhookWebhooksManagementWebhooksPost**](WebhooksManagementApi.md#createWebhookWebhooksManagementWebhooksPost) | **POST** /webhooks-management/webhooks/ | Create Webhook |
| [**deleteWebhookWebhooksManagementWebhooksWebhookIdDelete**](WebhooksManagementApi.md#deleteWebhookWebhooksManagementWebhooksWebhookIdDelete) | **DELETE** /webhooks-management/webhooks/{webhook_id} | Delete Webhook |
| [**getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet**](WebhooksManagementApi.md#getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet) | **GET** /webhooks-management/webhooks/{webhook_id}/deliveries | Get Deliveries |
| [**getWebhookWebhooksManagementWebhooksWebhookIdGet**](WebhooksManagementApi.md#getWebhookWebhooksManagementWebhooksWebhookIdGet) | **GET** /webhooks-management/webhooks/{webhook_id} | Get Webhook |
| [**listWebhooksWebhooksManagementWebhooksGet**](WebhooksManagementApi.md#listWebhooksWebhooksManagementWebhooksGet) | **GET** /webhooks-management/webhooks/ | List Webhooks |
| [**testWebhookWebhooksManagementWebhooksWebhookIdTestPost**](WebhooksManagementApi.md#testWebhookWebhooksManagementWebhooksWebhookIdTestPost) | **POST** /webhooks-management/webhooks/{webhook_id}/test | Test Webhook |
| [**updateWebhookWebhooksManagementWebhooksWebhookIdPatch**](WebhooksManagementApi.md#updateWebhookWebhooksManagementWebhooksWebhookIdPatch) | **PATCH** /webhooks-management/webhooks/{webhook_id} | Update Webhook |


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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    WebhookCreate webhookCreate = new WebhookCreate(); // WebhookCreate | 
    try {
      Object result = apiInstance.createWebhookWebhooksManagementWebhooksPost(webhookCreate);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#createWebhookWebhooksManagementWebhooksPost");
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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    try {
      Object result = apiInstance.deleteWebhookWebhooksManagementWebhooksWebhookIdDelete(webhookId);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#deleteWebhookWebhooksManagementWebhooksWebhookIdDelete");
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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    Integer limit = 100; // Integer | 
    try {
      Object result = apiInstance.getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet(webhookId, limit);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#getDeliveriesWebhooksManagementWebhooksWebhookIdDeliveriesGet");
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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    try {
      Object result = apiInstance.getWebhookWebhooksManagementWebhooksWebhookIdGet(webhookId);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#getWebhookWebhooksManagementWebhooksWebhookIdGet");
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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    try {
      Object result = apiInstance.listWebhooksWebhooksManagementWebhooksGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#listWebhooksWebhooksManagementWebhooksGet");
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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    try {
      Object result = apiInstance.testWebhookWebhooksManagementWebhooksWebhookIdTestPost(webhookId);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#testWebhookWebhooksManagementWebhooksWebhookIdTestPost");
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
import com.mailsafepro.api.WebhooksManagementApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    WebhooksManagementApi apiInstance = new WebhooksManagementApi(defaultClient);
    String webhookId = "webhookId_example"; // String | 
    WebhookUpdate webhookUpdate = new WebhookUpdate(); // WebhookUpdate | 
    try {
      Object result = apiInstance.updateWebhookWebhooksManagementWebhooksWebhookIdPatch(webhookId, webhookUpdate);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling WebhooksManagementApi#updateWebhookWebhooksManagementWebhooksWebhookIdPatch");
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

