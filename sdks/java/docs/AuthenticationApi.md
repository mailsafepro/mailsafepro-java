# AuthenticationApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**authHealthCheckAuthHealthAuthGet**](AuthenticationApi.md#authHealthCheckAuthHealthAuthGet) | **GET** /auth/health/auth | Auth Health Check |
| [**authHealthCheckAuthHealthAuthGet_0**](AuthenticationApi.md#authHealthCheckAuthHealthAuthGet_0) | **GET** /auth/health/auth | Auth Health Check |
| [**authHealthCheckAuthHealthAuthHead**](AuthenticationApi.md#authHealthCheckAuthHealthAuthHead) | **HEAD** /auth/health/auth | Auth Health Check |
| [**authHealthCheckAuthHealthAuthHead_0**](AuthenticationApi.md#authHealthCheckAuthHealthAuthHead_0) | **HEAD** /auth/health/auth | Auth Health Check |
| [**deleteAccountAuthDeleteDelete**](AuthenticationApi.md#deleteAccountAuthDeleteDelete) | **DELETE** /auth/delete | Delete Account |
| [**deleteAccountAuthDeleteDelete_0**](AuthenticationApi.md#deleteAccountAuthDeleteDelete_0) | **DELETE** /auth/delete | Delete Account |
| [**getCurrentUserAuthMeGet**](AuthenticationApi.md#getCurrentUserAuthMeGet) | **GET** /auth/me | Get Current User |
| [**getCurrentUserAuthMeGet_0**](AuthenticationApi.md#getCurrentUserAuthMeGet_0) | **GET** /auth/me | Get Current User |
| [**loginWebUserAuthLoginPost**](AuthenticationApi.md#loginWebUserAuthLoginPost) | **POST** /auth/login | Login Web User |
| [**loginWebUserAuthLoginPost_0**](AuthenticationApi.md#loginWebUserAuthLoginPost_0) | **POST** /auth/login | Login Web User |
| [**logoutAuthLogoutPost**](AuthenticationApi.md#logoutAuthLogoutPost) | **POST** /auth/logout | Logout |
| [**logoutAuthLogoutPost_0**](AuthenticationApi.md#logoutAuthLogoutPost_0) | **POST** /auth/logout | Logout |
| [**refreshTokenAuthRefreshPost**](AuthenticationApi.md#refreshTokenAuthRefreshPost) | **POST** /auth/refresh | Refresh Token |
| [**refreshTokenAuthRefreshPost_0**](AuthenticationApi.md#refreshTokenAuthRefreshPost_0) | **POST** /auth/refresh | Refresh Token |
| [**registerWebUserAuthRegisterPost**](AuthenticationApi.md#registerWebUserAuthRegisterPost) | **POST** /auth/register | Register Web User |
| [**registerWebUserAuthRegisterPost_0**](AuthenticationApi.md#registerWebUserAuthRegisterPost_0) | **POST** /auth/register | Register Web User |
| [**rotateApiKeyAuthRotateKeyPost**](AuthenticationApi.md#rotateApiKeyAuthRotateKeyPost) | **POST** /auth/rotate-key | Rotate Api Key |
| [**rotateApiKeyAuthRotateKeyPost_0**](AuthenticationApi.md#rotateApiKeyAuthRotateKeyPost_0) | **POST** /auth/rotate-key | Rotate Api Key |


<a id="authHealthCheckAuthHealthAuthGet"></a>
# **authHealthCheckAuthHealthAuthGet**
> Object authHealthCheckAuthHealthAuthGet()

Auth Health Check

Health check para autenticación: Redis, JWT y hashing.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.authHealthCheckAuthHealthAuthGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#authHealthCheckAuthHealthAuthGet");
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

<a id="authHealthCheckAuthHealthAuthGet_0"></a>
# **authHealthCheckAuthHealthAuthGet_0**
> Object authHealthCheckAuthHealthAuthGet_0()

Auth Health Check

Health check para autenticación: Redis, JWT y hashing.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.authHealthCheckAuthHealthAuthGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#authHealthCheckAuthHealthAuthGet_0");
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

<a id="authHealthCheckAuthHealthAuthHead"></a>
# **authHealthCheckAuthHealthAuthHead**
> Object authHealthCheckAuthHealthAuthHead()

Auth Health Check

Health check para autenticación: Redis, JWT y hashing.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.authHealthCheckAuthHealthAuthHead();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#authHealthCheckAuthHealthAuthHead");
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

<a id="authHealthCheckAuthHealthAuthHead_0"></a>
# **authHealthCheckAuthHealthAuthHead_0**
> Object authHealthCheckAuthHealthAuthHead_0()

Auth Health Check

Health check para autenticación: Redis, JWT y hashing.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.authHealthCheckAuthHealthAuthHead_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#authHealthCheckAuthHealthAuthHead_0");
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

<a id="deleteAccountAuthDeleteDelete"></a>
# **deleteAccountAuthDeleteDelete**
> Object deleteAccountAuthDeleteDelete()

Delete Account

Elimina la cuenta del usuario autenticado y todos sus datos relacionados.  ⚠️ ADVERTENCIA: Esta operación es IRREVERSIBLE.  Elimina: - Datos del usuario - Todas las API keys - Usage/quota - Suscripciones - Rate limits - Tokens relacionados  Security: - Solo el usuario puede eliminarse a sí mismo (o admin) - Requiere autenticación válida - Registra la acción en logs para auditoría - Rate limited para prevenir abuse

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.deleteAccountAuthDeleteDelete();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#deleteAccountAuthDeleteDelete");
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

<a id="deleteAccountAuthDeleteDelete_0"></a>
# **deleteAccountAuthDeleteDelete_0**
> Object deleteAccountAuthDeleteDelete_0()

Delete Account

Elimina la cuenta del usuario autenticado y todos sus datos relacionados.  ⚠️ ADVERTENCIA: Esta operación es IRREVERSIBLE.  Elimina: - Datos del usuario - Todas las API keys - Usage/quota - Suscripciones - Rate limits - Tokens relacionados  Security: - Solo el usuario puede eliminarse a sí mismo (o admin) - Requiere autenticación válida - Registra la acción en logs para auditoría - Rate limited para prevenir abuse

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.deleteAccountAuthDeleteDelete_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#deleteAccountAuthDeleteDelete_0");
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

<a id="getCurrentUserAuthMeGet"></a>
# **getCurrentUserAuthMeGet**
> Object getCurrentUserAuthMeGet()

Get Current User

Devuelve información básica del usuario actual.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.getCurrentUserAuthMeGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#getCurrentUserAuthMeGet");
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

<a id="getCurrentUserAuthMeGet_0"></a>
# **getCurrentUserAuthMeGet_0**
> Object getCurrentUserAuthMeGet_0()

Get Current User

Devuelve información básica del usuario actual.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.getCurrentUserAuthMeGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#getCurrentUserAuthMeGet_0");
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

<a id="loginWebUserAuthLoginPost"></a>
# **loginWebUserAuthLoginPost**
> Object loginWebUserAuthLoginPost(userLogin)

Login Web User

Login de usuario para panel web.  Security features: - Rate limiting por email + IP - Timing attack protection - Generic error messages - PII masking en logs

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    UserLogin userLogin = new UserLogin(); // UserLogin | 
    try {
      Object result = apiInstance.loginWebUserAuthLoginPost(userLogin);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#loginWebUserAuthLoginPost");
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
| **userLogin** | [**UserLogin**](UserLogin.md)|  | |

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

<a id="loginWebUserAuthLoginPost_0"></a>
# **loginWebUserAuthLoginPost_0**
> Object loginWebUserAuthLoginPost_0(userLogin)

Login Web User

Login de usuario para panel web.  Security features: - Rate limiting por email + IP - Timing attack protection - Generic error messages - PII masking en logs

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    UserLogin userLogin = new UserLogin(); // UserLogin | 
    try {
      Object result = apiInstance.loginWebUserAuthLoginPost_0(userLogin);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#loginWebUserAuthLoginPost_0");
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
| **userLogin** | [**UserLogin**](UserLogin.md)|  | |

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

<a id="logoutAuthLogoutPost"></a>
# **logoutAuthLogoutPost**
> Object logoutAuthLogoutPost()

Logout

Logout idempotente: - Si el access token es válido, lo añade a la blacklist. - Si el access token está expirado, responde 200 indicando que ya estaba expirado. - Solo devuelve 401 si el token es completamente inválido (firma/claims corruptos). - Intenta revocar el refresh token si se proporciona.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.logoutAuthLogoutPost();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#logoutAuthLogoutPost");
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

<a id="logoutAuthLogoutPost_0"></a>
# **logoutAuthLogoutPost_0**
> Object logoutAuthLogoutPost_0()

Logout

Logout idempotente: - Si el access token es válido, lo añade a la blacklist. - Si el access token está expirado, responde 200 indicando que ya estaba expirado. - Solo devuelve 401 si el token es completamente inválido (firma/claims corruptos). - Intenta revocar el refresh token si se proporciona.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.logoutAuthLogoutPost_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#logoutAuthLogoutPost_0");
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

<a id="refreshTokenAuthRefreshPost"></a>
# **refreshTokenAuthRefreshPost**
> Object refreshTokenAuthRefreshPost()

Refresh Token

Crea un nuevo par de tokens a partir de un refresh token válido y no revocado.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.refreshTokenAuthRefreshPost();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#refreshTokenAuthRefreshPost");
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

<a id="refreshTokenAuthRefreshPost_0"></a>
# **refreshTokenAuthRefreshPost_0**
> Object refreshTokenAuthRefreshPost_0()

Refresh Token

Crea un nuevo par de tokens a partir de un refresh token válido y no revocado.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    try {
      Object result = apiInstance.refreshTokenAuthRefreshPost_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#refreshTokenAuthRefreshPost_0");
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

<a id="registerWebUserAuthRegisterPost"></a>
# **registerWebUserAuthRegisterPost**
> Object registerWebUserAuthRegisterPost(userRegister)

Register Web User

Registro de usuario para panel web: crea usuario, API key y tokens.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    UserRegister userRegister = new UserRegister(); // UserRegister | 
    try {
      Object result = apiInstance.registerWebUserAuthRegisterPost(userRegister);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#registerWebUserAuthRegisterPost");
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
| **userRegister** | [**UserRegister**](UserRegister.md)|  | |

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
| **201** | Successful Response |  -  |
| **422** | Validation Error |  -  |

<a id="registerWebUserAuthRegisterPost_0"></a>
# **registerWebUserAuthRegisterPost_0**
> Object registerWebUserAuthRegisterPost_0(userRegister)

Register Web User

Registro de usuario para panel web: crea usuario, API key y tokens.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    UserRegister userRegister = new UserRegister(); // UserRegister | 
    try {
      Object result = apiInstance.registerWebUserAuthRegisterPost_0(userRegister);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#registerWebUserAuthRegisterPost_0");
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
| **userRegister** | [**UserRegister**](UserRegister.md)|  | |

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
| **201** | Successful Response |  -  |
| **422** | Validation Error |  -  |

<a id="rotateApiKeyAuthRotateKeyPost"></a>
# **rotateApiKeyAuthRotateKeyPost**
> Object rotateApiKeyAuthRotateKeyPost(keyRotationRequest)

Rotate Api Key

Rotación de API keys con período de gracia; acceso restringido a admin.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    KeyRotationRequest keyRotationRequest = new KeyRotationRequest(); // KeyRotationRequest | 
    try {
      Object result = apiInstance.rotateApiKeyAuthRotateKeyPost(keyRotationRequest);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#rotateApiKeyAuthRotateKeyPost");
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
| **keyRotationRequest** | [**KeyRotationRequest**](KeyRotationRequest.md)|  | |

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

<a id="rotateApiKeyAuthRotateKeyPost_0"></a>
# **rotateApiKeyAuthRotateKeyPost_0**
> Object rotateApiKeyAuthRotateKeyPost_0(keyRotationRequest)

Rotate Api Key

Rotación de API keys con período de gracia; acceso restringido a admin.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.auth.*;
import com.mailsafepro.models.*;
import com.mailsafepro.api.AuthenticationApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");
    
    // Configure HTTP bearer authorization: Bearer
    HttpBearerAuth Bearer = (HttpBearerAuth) defaultClient.getAuthentication("Bearer");
    Bearer.setBearerToken("BEARER TOKEN");

    AuthenticationApi apiInstance = new AuthenticationApi(defaultClient);
    KeyRotationRequest keyRotationRequest = new KeyRotationRequest(); // KeyRotationRequest | 
    try {
      Object result = apiInstance.rotateApiKeyAuthRotateKeyPost_0(keyRotationRequest);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling AuthenticationApi#rotateApiKeyAuthRotateKeyPost_0");
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
| **keyRotationRequest** | [**KeyRotationRequest**](KeyRotationRequest.md)|  | |

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

