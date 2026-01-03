# HealthApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**basicHealthHealthGet**](HealthApi.md#basicHealthHealthGet) | **GET** /health | Basic health check |
| [**basicHealthHealthGet_0**](HealthApi.md#basicHealthHealthGet_0) | **GET** /health | Basic health check |
| [**circuitBreakerStatusAdminCircuitBreakerStatusGet**](HealthApi.md#circuitBreakerStatusAdminCircuitBreakerStatusGet) | **GET** /admin/circuit-breaker-status | Circuit Breaker Status |
| [**detailedHealthHealthDetailedGet**](HealthApi.md#detailedHealthHealthDetailedGet) | **GET** /health/detailed | Detailed health check |
| [**detailedHealthHealthDetailedGet_0**](HealthApi.md#detailedHealthHealthDetailedGet_0) | **GET** /health/detailed | Detailed health check |
| [**healthcheckHealthcheckGet**](HealthApi.md#healthcheckHealthcheckGet) | **GET** /healthcheck | Healthcheck |
| [**healthcheckHealthcheckHead**](HealthApi.md#healthcheckHealthcheckHead) | **HEAD** /healthcheck | Healthcheck |
| [**livenessCheckHealthLivenessGet**](HealthApi.md#livenessCheckHealthLivenessGet) | **GET** /health/liveness | Liveness Check |
| [**livenessHealthLiveGet**](HealthApi.md#livenessHealthLiveGet) | **GET** /health/live | Liveness probe (Kubernetes) |
| [**livenessHealthLiveGet_0**](HealthApi.md#livenessHealthLiveGet_0) | **GET** /health/live | Liveness probe (Kubernetes) |
| [**readinessCheckHealthReadinessGet**](HealthApi.md#readinessCheckHealthReadinessGet) | **GET** /health/readiness | Readiness Check |
| [**readinessHealthReadyGet**](HealthApi.md#readinessHealthReadyGet) | **GET** /health/ready | Readiness probe (Kubernetes) |
| [**readinessHealthReadyGet_0**](HealthApi.md#readinessHealthReadyGet_0) | **GET** /health/ready | Readiness probe (Kubernetes) |
| [**serviceStatusStatusGet**](HealthApi.md#serviceStatusStatusGet) | **GET** /status | Service Status |
| [**startupCheckHealthStartupGet**](HealthApi.md#startupCheckHealthStartupGet) | **GET** /health/startup | Startup Check |


<a id="basicHealthHealthGet"></a>
# **basicHealthHealthGet**
> Object basicHealthHealthGet()

Basic health check

Basic health check for load balancers.  Returns 200 if service is running. Fast response, no dependency checks.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.basicHealthHealthGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#basicHealthHealthGet");
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

<a id="basicHealthHealthGet_0"></a>
# **basicHealthHealthGet_0**
> Object basicHealthHealthGet_0()

Basic health check

Basic health check for load balancers.  Returns 200 if service is running. Fast response, no dependency checks.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.basicHealthHealthGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#basicHealthHealthGet_0");
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

<a id="circuitBreakerStatusAdminCircuitBreakerStatusGet"></a>
# **circuitBreakerStatusAdminCircuitBreakerStatusGet**
> Object circuitBreakerStatusAdminCircuitBreakerStatusGet()

Circuit Breaker Status

✅ Circuit breaker status for all services. Shows state of Redis, SMTP, DNS, and other circuit breakers.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.circuitBreakerStatusAdminCircuitBreakerStatusGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#circuitBreakerStatusAdminCircuitBreakerStatusGet");
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

<a id="detailedHealthHealthDetailedGet"></a>
# **detailedHealthHealthDetailedGet**
> Object detailedHealthHealthDetailedGet()

Detailed health check

Detailed health check with all component statuses.  Returns comprehensive health information for monitoring.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.detailedHealthHealthDetailedGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#detailedHealthHealthDetailedGet");
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

<a id="detailedHealthHealthDetailedGet_0"></a>
# **detailedHealthHealthDetailedGet_0**
> Object detailedHealthHealthDetailedGet_0()

Detailed health check

Detailed health check with all component statuses.  Returns comprehensive health information for monitoring.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.detailedHealthHealthDetailedGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#detailedHealthHealthDetailedGet_0");
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

<a id="healthcheckHealthcheckGet"></a>
# **healthcheckHealthcheckGet**
> Object healthcheckHealthcheckGet()

Healthcheck

Basic health check endpoint (backward compatibility)

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.healthcheckHealthcheckGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#healthcheckHealthcheckGet");
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

<a id="healthcheckHealthcheckHead"></a>
# **healthcheckHealthcheckHead**
> Object healthcheckHealthcheckHead()

Healthcheck

Basic health check endpoint (backward compatibility)

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.healthcheckHealthcheckHead();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#healthcheckHealthcheckHead");
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

<a id="livenessCheckHealthLivenessGet"></a>
# **livenessCheckHealthLivenessGet**
> Object livenessCheckHealthLivenessGet()

Liveness Check

✅ MEJORA: Kubernetes liveness probe  Returns 200 if the application is alive (not deadlocked) Used by Kubernetes to restart the pod if unhealthy

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.livenessCheckHealthLivenessGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#livenessCheckHealthLivenessGet");
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

<a id="livenessHealthLiveGet"></a>
# **livenessHealthLiveGet**
> Object livenessHealthLiveGet()

Liveness probe (Kubernetes)

Kubernetes liveness probe.  Returns 200 if the application is running. Should restart pod if this fails.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.livenessHealthLiveGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#livenessHealthLiveGet");
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

<a id="livenessHealthLiveGet_0"></a>
# **livenessHealthLiveGet_0**
> Object livenessHealthLiveGet_0()

Liveness probe (Kubernetes)

Kubernetes liveness probe.  Returns 200 if the application is running. Should restart pod if this fails.

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.livenessHealthLiveGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#livenessHealthLiveGet_0");
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

<a id="readinessCheckHealthReadinessGet"></a>
# **readinessCheckHealthReadinessGet**
> Object readinessCheckHealthReadinessGet()

Readiness Check

✅ MEJORA: Kubernetes readiness probe  Returns 200 if the application is ready to serve traffic Checks all critical dependencies (PostgreSQL, Redis, ARQ)

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.readinessCheckHealthReadinessGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#readinessCheckHealthReadinessGet");
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

<a id="readinessHealthReadyGet"></a>
# **readinessHealthReadyGet**
> Object readinessHealthReadyGet()

Readiness probe (Kubernetes)

Kubernetes readiness probe.  Returns 200 if service is ready to accept traffic. Checks critical dependencies (Redis).

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.readinessHealthReadyGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#readinessHealthReadyGet");
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

<a id="readinessHealthReadyGet_0"></a>
# **readinessHealthReadyGet_0**
> Object readinessHealthReadyGet_0()

Readiness probe (Kubernetes)

Kubernetes readiness probe.  Returns 200 if service is ready to accept traffic. Checks critical dependencies (Redis).

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.readinessHealthReadyGet_0();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#readinessHealthReadyGet_0");
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

<a id="serviceStatusStatusGet"></a>
# **serviceStatusStatusGet**
> Object serviceStatusStatusGet()

Service Status

✅ MEJORA: Detailed service status with feature flags  Shows which features are available and which are running in degraded mode

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.serviceStatusStatusGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#serviceStatusStatusGet");
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

<a id="startupCheckHealthStartupGet"></a>
# **startupCheckHealthStartupGet**
> Object startupCheckHealthStartupGet()

Startup Check

✅ MEJORA: Kubernetes startup probe  Returns 200 once the application has completed startup Used to delay readiness checks until startup is complete

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.HealthApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    HealthApi apiInstance = new HealthApi(defaultClient);
    try {
      Object result = apiInstance.startupCheckHealthStartupGet();
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling HealthApi#startupCheckHealthStartupGet");
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

