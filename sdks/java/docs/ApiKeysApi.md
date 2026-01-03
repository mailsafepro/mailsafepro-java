# ApiKeysApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**createApiKeyApiKeysPost**](ApiKeysApi.md#createApiKeyApiKeysPost) | **POST** /api-keys | Create Api Key |
| [**createApiKeyApiKeysPost_0**](ApiKeysApi.md#createApiKeyApiKeysPost_0) | **POST** /api-keys | Create Api Key |
| [**forceSyncApiKeysForceSyncPost**](ApiKeysApi.md#forceSyncApiKeysForceSyncPost) | **POST** /api-keys/force-sync | Force Sync |
| [**forceSyncApiKeysForceSyncPost_0**](ApiKeysApi.md#forceSyncApiKeysForceSyncPost_0) | **POST** /api-keys/force-sync | Force Sync |
| [**getApiKeyValueApiKeysKeyHashValueGet**](ApiKeysApi.md#getApiKeyValueApiKeysKeyHashValueGet) | **GET** /api-keys/{key_hash}/value | Get Api Key Value |
| [**getApiKeyValueApiKeysKeyHashValueGet_0**](ApiKeysApi.md#getApiKeyValueApiKeysKeyHashValueGet_0) | **GET** /api-keys/{key_hash}/value | Get Api Key Value |
| [**getUsageApiKeysUsageGet**](ApiKeysApi.md#getUsageApiKeysUsageGet) | **GET** /api-keys/usage | Get Usage |
| [**getUsageApiKeysUsageGet_0**](ApiKeysApi.md#getUsageApiKeysUsageGet_0) | **GET** /api-keys/usage | Get Usage |
| [**listApiKeysApiKeysGet**](ApiKeysApi.md#listApiKeysApiKeysGet) | **GET** /api-keys | List Api Keys |
| [**listApiKeysApiKeysGet_0**](ApiKeysApi.md#listApiKeysApiKeysGet_0) | **GET** /api-keys | List Api Keys |
| [**repairUserDataEndpointApiKeysRepairDataPost**](ApiKeysApi.md#repairUserDataEndpointApiKeysRepairDataPost) | **POST** /api-keys/repair-data | Repair User Data Endpoint |
| [**repairUserDataEndpointApiKeysRepairDataPost_0**](ApiKeysApi.md#repairUserDataEndpointApiKeysRepairDataPost_0) | **POST** /api-keys/repair-data | Repair User Data Endpoint |
| [**revokeApiKeyApiKeysKeyHashRevokeDelete**](ApiKeysApi.md#revokeApiKeyApiKeysKeyHashRevokeDelete) | **DELETE** /api-keys/{key_hash}/revoke | Revoke Api Key |
| [**revokeApiKeyApiKeysKeyHashRevokeDelete_0**](ApiKeysApi.md#revokeApiKeyApiKeysKeyHashRevokeDelete_0) | **DELETE** /api-keys/{key_hash}/revoke | Revoke Api Key |
| [**rotateApiKeyApiKeysKeyHashRotatePost**](ApiKeysApi.md#rotateApiKeyApiKeysKeyHashRotatePost) | **POST** /api-keys/{key_hash}/rotate | Rotate Api Key |
| [**rotateApiKeyApiKeysKeyHashRotatePost_0**](ApiKeysApi.md#rotateApiKeyApiKeysKeyHashRotatePost_0) | **POST** /api-keys/{key_hash}/rotate | Rotate Api Key |
| [**syncPlanKeysApiKeysSyncPlanKeysPost**](ApiKeysApi.md#syncPlanKeysApiKeysSyncPlanKeysPost) | **POST** /api-keys/sync-plan-keys | Sync Plan Keys |
| [**syncPlanKeysApiKeysSyncPlanKeysPost_0**](ApiKeysApi.md#syncPlanKeysApiKeysSyncPlanKeysPost_0) | **POST** /api-keys/sync-plan-keys | Sync Plan Keys |


<a id="createApiKeyApiKeysPost"></a>
# **createApiKeyApiKeysPost**
> Object createApiKeyApiKeysPost(apIKeyCreateRequest)

Create Api Key

Create a new API key with atomic transaction. Generates cryptographically secure API keys with proper scoping based on user&#39;s current plan. Enforces maximum key limits.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    APIKeyCreateRequest apIKeyCreateRequest = new APIKeyCreateRequest(); // APIKeyCreateRequest | 
    try {
      Object result = apiInstance.createApiKeyApiKeysPost(apIKeyCreateRequest);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#createApiKeyApiKeysPost");
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
| **apIKeyCreateRequest** | [**APIKeyCreateRequest**](APIKeyCreateRequest.md)|  | |

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

<a id="createApiKeyApiKeysPost_0"></a>
# **createApiKeyApiKeysPost_0**
> Object createApiKeyApiKeysPost_0(apIKeyCreateRequest)

Create Api Key

Create a new API key with atomic transaction. Generates cryptographically secure API keys with proper scoping based on user&#39;s current plan. Enforces maximum key limits.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    APIKeyCreateRequest apIKeyCreateRequest = new APIKeyCreateRequest(); // APIKeyCreateRequest | 
    try {
      Object result = apiInstance.createApiKeyApiKeysPost_0(apIKeyCreateRequest);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#createApiKeyApiKeysPost_0");
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
| **apIKeyCreateRequest** | [**APIKeyCreateRequest**](APIKeyCreateRequest.md)|  | |

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

<a id="forceSyncApiKeysForceSyncPost"></a>
# **forceSyncApiKeysForceSyncPost**
> Object forceSyncApiKeysForceSyncPost()

Force Sync

Force synchronization of user data with rate limiting. Synchronizes API keys with current plan and clears relevant caches. Limited to one sync per 5 minutes per user.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      Object result = apiInstance.forceSyncApiKeysForceSyncPost();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#forceSyncApiKeysForceSyncPost");
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

<a id="forceSyncApiKeysForceSyncPost_0"></a>
# **forceSyncApiKeysForceSyncPost_0**
> Object forceSyncApiKeysForceSyncPost_0()

Force Sync

Force synchronization of user data with rate limiting. Synchronizes API keys with current plan and clears relevant caches. Limited to one sync per 5 minutes per user.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      Object result = apiInstance.forceSyncApiKeysForceSyncPost_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#forceSyncApiKeysForceSyncPost_0");
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

<a id="getApiKeyValueApiKeysKeyHashValueGet"></a>
# **getApiKeyValueApiKeysKeyHashValueGet**
> Object getApiKeyValueApiKeysKeyHashValueGet(keyHash)

Get Api Key Value

Retrieve API key metadata (security-safe). Returns key information without exposing the actual key value. Used for key management and verification purposes.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String keyHash = "keyHash_example"; // String | 
    try {
      Object result = apiInstance.getApiKeyValueApiKeysKeyHashValueGet(keyHash);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#getApiKeyValueApiKeysKeyHashValueGet");
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
| **keyHash** | **String**|  | |

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

<a id="getApiKeyValueApiKeysKeyHashValueGet_0"></a>
# **getApiKeyValueApiKeysKeyHashValueGet_0**
> Object getApiKeyValueApiKeysKeyHashValueGet_0(keyHash)

Get Api Key Value

Retrieve API key metadata (security-safe). Returns key information without exposing the actual key value. Used for key management and verification purposes.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String keyHash = "keyHash_example"; // String | 
    try {
      Object result = apiInstance.getApiKeyValueApiKeysKeyHashValueGet_0(keyHash);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#getApiKeyValueApiKeysKeyHashValueGet_0");
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
| **keyHash** | **String**|  | |

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

<a id="getUsageApiKeysUsageGet"></a>
# **getUsageApiKeysUsageGet**
> Object getUsageApiKeysUsageGet(xAPIKey, authorization)

Get Usage

Get current API usage statistics. Returns usage count, limits, and remaining requests for today. Works with both API keys and JWT tokens.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.getUsageApiKeysUsageGet(xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#getUsageApiKeysUsageGet");
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

<a id="getUsageApiKeysUsageGet_0"></a>
# **getUsageApiKeysUsageGet_0**
> Object getUsageApiKeysUsageGet_0(xAPIKey, authorization)

Get Usage

Get current API usage statistics. Returns usage count, limits, and remaining requests for today. Works with both API keys and JWT tokens.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      Object result = apiInstance.getUsageApiKeysUsageGet_0(xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#getUsageApiKeysUsageGet_0");
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

<a id="listApiKeysApiKeysGet"></a>
# **listApiKeysApiKeysGet**
> APIKeyListResponse listApiKeysApiKeysGet()

List Api Keys

List all API keys for current user with consistent IDs. Returns comprehensive key metadata including status, scopes, and usage information. Handles corrupted key data gracefully.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      APIKeyListResponse result = apiInstance.listApiKeysApiKeysGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#listApiKeysApiKeysGet");
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

[**APIKeyListResponse**](APIKeyListResponse.md)

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="listApiKeysApiKeysGet_0"></a>
# **listApiKeysApiKeysGet_0**
> APIKeyListResponse listApiKeysApiKeysGet_0()

List Api Keys

List all API keys for current user with consistent IDs. Returns comprehensive key metadata including status, scopes, and usage information. Handles corrupted key data gracefully.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      APIKeyListResponse result = apiInstance.listApiKeysApiKeysGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#listApiKeysApiKeysGet_0");
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

[**APIKeyListResponse**](APIKeyListResponse.md)

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="repairUserDataEndpointApiKeysRepairDataPost"></a>
# **repairUserDataEndpointApiKeysRepairDataPost**
> Map&lt;String, String&gt; repairUserDataEndpointApiKeysRepairDataPost()

Repair User Data Endpoint

Emergency data repair endpoint - ADMINISTRATORS ONLY WARNING: Critical operation; relies on admin scope verification at runtime.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      Map<String, String> result = apiInstance.repairUserDataEndpointApiKeysRepairDataPost();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#repairUserDataEndpointApiKeysRepairDataPost");
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

**Map&lt;String, String&gt;**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="repairUserDataEndpointApiKeysRepairDataPost_0"></a>
# **repairUserDataEndpointApiKeysRepairDataPost_0**
> Map&lt;String, String&gt; repairUserDataEndpointApiKeysRepairDataPost_0()

Repair User Data Endpoint

Emergency data repair endpoint - ADMINISTRATORS ONLY WARNING: Critical operation; relies on admin scope verification at runtime.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      Map<String, String> result = apiInstance.repairUserDataEndpointApiKeysRepairDataPost_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#repairUserDataEndpointApiKeysRepairDataPost_0");
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

**Map&lt;String, String&gt;**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="revokeApiKeyApiKeysKeyHashRevokeDelete"></a>
# **revokeApiKeyApiKeysKeyHashRevokeDelete**
> Object revokeApiKeyApiKeysKeyHashRevokeDelete(keyHash)

Revoke Api Key

Revoke an API key with atomic transaction. Immediately invalidates the key and removes it from active sets. Provides audit trail for security compliance.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String keyHash = "keyHash_example"; // String | 
    try {
      Object result = apiInstance.revokeApiKeyApiKeysKeyHashRevokeDelete(keyHash);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#revokeApiKeyApiKeysKeyHashRevokeDelete");
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
| **keyHash** | **String**|  | |

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

<a id="revokeApiKeyApiKeysKeyHashRevokeDelete_0"></a>
# **revokeApiKeyApiKeysKeyHashRevokeDelete_0**
> Object revokeApiKeyApiKeysKeyHashRevokeDelete_0(keyHash)

Revoke Api Key

Revoke an API key with atomic transaction. Immediately invalidates the key and removes it from active sets. Provides audit trail for security compliance.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String keyHash = "keyHash_example"; // String | 
    try {
      Object result = apiInstance.revokeApiKeyApiKeysKeyHashRevokeDelete_0(keyHash);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#revokeApiKeyApiKeysKeyHashRevokeDelete_0");
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
| **keyHash** | **String**|  | |

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

<a id="rotateApiKeyApiKeysKeyHashRotatePost"></a>
# **rotateApiKeyApiKeysKeyHashRotatePost**
> Object rotateApiKeyApiKeysKeyHashRotatePost(keyHash)

Rotate Api Key

Rotate API key with grace period. Generates a new key while keeping the old one active for 7 days to allow for smooth transition in client applications.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String keyHash = "keyHash_example"; // String | 
    try {
      Object result = apiInstance.rotateApiKeyApiKeysKeyHashRotatePost(keyHash);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#rotateApiKeyApiKeysKeyHashRotatePost");
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
| **keyHash** | **String**|  | |

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

<a id="rotateApiKeyApiKeysKeyHashRotatePost_0"></a>
# **rotateApiKeyApiKeysKeyHashRotatePost_0**
> Object rotateApiKeyApiKeysKeyHashRotatePost_0(keyHash)

Rotate Api Key

Rotate API key with grace period. Generates a new key while keeping the old one active for 7 days to allow for smooth transition in client applications.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    String keyHash = "keyHash_example"; // String | 
    try {
      Object result = apiInstance.rotateApiKeyApiKeysKeyHashRotatePost_0(keyHash);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#rotateApiKeyApiKeysKeyHashRotatePost_0");
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
| **keyHash** | **String**|  | |

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

<a id="syncPlanKeysApiKeysSyncPlanKeysPost"></a>
# **syncPlanKeysApiKeysSyncPlanKeysPost**
> Object syncPlanKeysApiKeysSyncPlanKeysPost()

Sync Plan Keys

Synchronize current plan with all user API keys. Ensures all existing keys have the correct scopes and permissions based on the user&#39;s current subscription plan.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      Object result = apiInstance.syncPlanKeysApiKeysSyncPlanKeysPost();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#syncPlanKeysApiKeysSyncPlanKeysPost");
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

<a id="syncPlanKeysApiKeysSyncPlanKeysPost_0"></a>
# **syncPlanKeysApiKeysSyncPlanKeysPost_0**
> Object syncPlanKeysApiKeysSyncPlanKeysPost_0()

Sync Plan Keys

Synchronize current plan with all user API keys. Ensures all existing keys have the correct scopes and permissions based on the user&#39;s current subscription plan.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.ApiKeysApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    ApiKeysApi apiInstance = new ApiKeysApi(defaultClient);
    try {
      Object result = apiInstance.syncPlanKeysApiKeysSyncPlanKeysPost_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling ApiKeysApi#syncPlanKeysApiKeysSyncPlanKeysPost_0");
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

