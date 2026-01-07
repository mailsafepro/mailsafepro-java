# BillingApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**changePlanBillingBillingChangePlanPost**](BillingApi.md#changePlanBillingBillingChangePlanPost) | **POST** /billing/billing/change-plan | Change Plan |
| [**changePlanBillingBillingChangePlanPost_0**](BillingApi.md#changePlanBillingBillingChangePlanPost_0) | **POST** /billing/billing/change-plan | Change Plan |
| [**createCheckoutSessionBillingBillingCreateCheckoutSessionPost**](BillingApi.md#createCheckoutSessionBillingBillingCreateCheckoutSessionPost) | **POST** /billing/billing/create-checkout-session | Create Checkout Session |
| [**createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0**](BillingApi.md#createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0) | **POST** /billing/billing/create-checkout-session | Create Checkout Session |
| [**getSubscriptionBillingBillingSubscriptionGet**](BillingApi.md#getSubscriptionBillingBillingSubscriptionGet) | **GET** /billing/billing/subscription | Get Subscription |
| [**getSubscriptionBillingBillingSubscriptionGet_0**](BillingApi.md#getSubscriptionBillingBillingSubscriptionGet_0) | **GET** /billing/billing/subscription | Get Subscription |
| [**stripeWebhookBillingBillingWebhookPost**](BillingApi.md#stripeWebhookBillingBillingWebhookPost) | **POST** /billing/billing/webhook | Stripe Webhook |
| [**stripeWebhookBillingBillingWebhookPost_0**](BillingApi.md#stripeWebhookBillingBillingWebhookPost_0) | **POST** /billing/billing/webhook | Stripe Webhook |
| [**testNotificationBillingBillingTestNotificationPost**](BillingApi.md#testNotificationBillingBillingTestNotificationPost) | **POST** /billing/billing/test-notification | Test Notification |
| [**testNotificationBillingBillingTestNotificationPost_0**](BillingApi.md#testNotificationBillingBillingTestNotificationPost_0) | **POST** /billing/billing/test-notification | Test Notification |


<a id="changePlanBillingBillingChangePlanPost"></a>
# **changePlanBillingBillingChangePlanPost**
> Object changePlanBillingBillingChangePlanPost(bodyChangePlanBillingBillingChangePlanPost)

Change Plan

Cambiar el plan del usuario.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    BillingApi apiInstance = new BillingApi(defaultClient);
    BodyChangePlanBillingBillingChangePlanPost bodyChangePlanBillingBillingChangePlanPost = new BodyChangePlanBillingBillingChangePlanPost(); // BodyChangePlanBillingBillingChangePlanPost | 
    try {
      Object result = apiInstance.changePlanBillingBillingChangePlanPost(bodyChangePlanBillingBillingChangePlanPost);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#changePlanBillingBillingChangePlanPost");
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
| **bodyChangePlanBillingBillingChangePlanPost** | [**BodyChangePlanBillingBillingChangePlanPost**](BodyChangePlanBillingBillingChangePlanPost.md)|  | |

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

<a id="changePlanBillingBillingChangePlanPost_0"></a>
# **changePlanBillingBillingChangePlanPost_0**
> Object changePlanBillingBillingChangePlanPost_0(bodyChangePlanBillingBillingChangePlanPost)

Change Plan

Cambiar el plan del usuario.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    BillingApi apiInstance = new BillingApi(defaultClient);
    BodyChangePlanBillingBillingChangePlanPost bodyChangePlanBillingBillingChangePlanPost = new BodyChangePlanBillingBillingChangePlanPost(); // BodyChangePlanBillingBillingChangePlanPost | 
    try {
      Object result = apiInstance.changePlanBillingBillingChangePlanPost_0(bodyChangePlanBillingBillingChangePlanPost);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#changePlanBillingBillingChangePlanPost_0");
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
| **bodyChangePlanBillingBillingChangePlanPost** | [**BodyChangePlanBillingBillingChangePlanPost**](BodyChangePlanBillingBillingChangePlanPost.md)|  | |

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

<a id="createCheckoutSessionBillingBillingCreateCheckoutSessionPost"></a>
# **createCheckoutSessionBillingBillingCreateCheckoutSessionPost**
> CheckoutSessionResponse createCheckoutSessionBillingBillingCreateCheckoutSessionPost(checkoutRequest)

Create Checkout Session

Crea una checkout session de Stripe para suscripción.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    BillingApi apiInstance = new BillingApi(defaultClient);
    CheckoutRequest checkoutRequest = new CheckoutRequest(); // CheckoutRequest | 
    try {
      CheckoutSessionResponse result = apiInstance.createCheckoutSessionBillingBillingCreateCheckoutSessionPost(checkoutRequest);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#createCheckoutSessionBillingBillingCreateCheckoutSessionPost");
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
| **checkoutRequest** | [**CheckoutRequest**](CheckoutRequest.md)|  | |

### Return type

[**CheckoutSessionResponse**](CheckoutSessionResponse.md)

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

<a id="createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0"></a>
# **createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0**
> CheckoutSessionResponse createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0(checkoutRequest)

Create Checkout Session

Crea una checkout session de Stripe para suscripción.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    BillingApi apiInstance = new BillingApi(defaultClient);
    CheckoutRequest checkoutRequest = new CheckoutRequest(); // CheckoutRequest | 
    try {
      CheckoutSessionResponse result = apiInstance.createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0(checkoutRequest);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#createCheckoutSessionBillingBillingCreateCheckoutSessionPost_0");
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
| **checkoutRequest** | [**CheckoutRequest**](CheckoutRequest.md)|  | |

### Return type

[**CheckoutSessionResponse**](CheckoutSessionResponse.md)

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

<a id="getSubscriptionBillingBillingSubscriptionGet"></a>
# **getSubscriptionBillingBillingSubscriptionGet**
> SubscriptionResponse getSubscriptionBillingBillingSubscriptionGet(xAPIKey, authorization)

Get Subscription

Devuelve información de suscripción (plan y próxima fecha de cobro).

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    BillingApi apiInstance = new BillingApi(defaultClient);
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      SubscriptionResponse result = apiInstance.getSubscriptionBillingBillingSubscriptionGet(xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#getSubscriptionBillingBillingSubscriptionGet");
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

[**SubscriptionResponse**](SubscriptionResponse.md)

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

<a id="getSubscriptionBillingBillingSubscriptionGet_0"></a>
# **getSubscriptionBillingBillingSubscriptionGet_0**
> SubscriptionResponse getSubscriptionBillingBillingSubscriptionGet_0(xAPIKey, authorization)

Get Subscription

Devuelve información de suscripción (plan y próxima fecha de cobro).

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    BillingApi apiInstance = new BillingApi(defaultClient);
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      SubscriptionResponse result = apiInstance.getSubscriptionBillingBillingSubscriptionGet_0(xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#getSubscriptionBillingBillingSubscriptionGet_0");
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

[**SubscriptionResponse**](SubscriptionResponse.md)

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

<a id="stripeWebhookBillingBillingWebhookPost"></a>
# **stripeWebhookBillingBillingWebhookPost**
> WebhookResponse stripeWebhookBillingBillingWebhookPost()

Stripe Webhook

Webhook de Stripe.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    BillingApi apiInstance = new BillingApi(defaultClient);
    try {
      WebhookResponse result = apiInstance.stripeWebhookBillingBillingWebhookPost();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#stripeWebhookBillingBillingWebhookPost");
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

[**WebhookResponse**](WebhookResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="stripeWebhookBillingBillingWebhookPost_0"></a>
# **stripeWebhookBillingBillingWebhookPost_0**
> WebhookResponse stripeWebhookBillingBillingWebhookPost_0()

Stripe Webhook

Webhook de Stripe.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    BillingApi apiInstance = new BillingApi(defaultClient);
    try {
      WebhookResponse result = apiInstance.stripeWebhookBillingBillingWebhookPost_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#stripeWebhookBillingBillingWebhookPost_0");
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

[**WebhookResponse**](WebhookResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |

<a id="testNotificationBillingBillingTestNotificationPost"></a>
# **testNotificationBillingBillingTestNotificationPost**
> Map&lt;String, ResponseTestNotificationBillingBillingTestNotificationPostValue&gt; testNotificationBillingBillingTestNotificationPost(requestBody)

Test Notification

Envía un email de prueba de cambio de plan.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    BillingApi apiInstance = new BillingApi(defaultClient);
    Map<String, String> requestBody = new HashMap(); // Map<String, String> | 
    try {
      Map<String, ResponseTestNotificationBillingBillingTestNotificationPostValue> result = apiInstance.testNotificationBillingBillingTestNotificationPost(requestBody);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#testNotificationBillingBillingTestNotificationPost");
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
| **requestBody** | [**Map&lt;String, String&gt;**](String.md)|  | |

### Return type

[**Map&lt;String, ResponseTestNotificationBillingBillingTestNotificationPostValue&gt;**](ResponseTestNotificationBillingBillingTestNotificationPostValue.md)

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

<a id="testNotificationBillingBillingTestNotificationPost_0"></a>
# **testNotificationBillingBillingTestNotificationPost_0**
> Map&lt;String, ResponseTestNotificationBillingBillingTestNotificationPostValue&gt; testNotificationBillingBillingTestNotificationPost_0(requestBody)

Test Notification

Envía un email de prueba de cambio de plan.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.BillingApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    BillingApi apiInstance = new BillingApi(defaultClient);
    Map<String, String> requestBody = new HashMap(); // Map<String, String> | 
    try {
      Map<String, ResponseTestNotificationBillingBillingTestNotificationPostValue> result = apiInstance.testNotificationBillingBillingTestNotificationPost_0(requestBody);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling BillingApi#testNotificationBillingBillingTestNotificationPost_0");
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
| **requestBody** | [**Map&lt;String, String&gt;**](String.md)|  | |

### Return type

[**Map&lt;String, ResponseTestNotificationBillingBillingTestNotificationPostValue&gt;**](ResponseTestNotificationBillingBillingTestNotificationPostValue.md)

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

