# JobsApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**createJobJobsV1JobsPost**](JobsApi.md#createJobJobsV1JobsPost) | **POST** /jobs/v1/jobs | Create validation job |
| [**createJobJobsV1JobsPost_0**](JobsApi.md#createJobJobsV1JobsPost_0) | **POST** /jobs/v1/jobs | Create validation job |
| [**getJobResultsJobsV1JobsJobIdResultsGet**](JobsApi.md#getJobResultsJobsV1JobsJobIdResultsGet) | **GET** /jobs/v1/jobs/{job_id}/results | Get job results (paged) |
| [**getJobResultsJobsV1JobsJobIdResultsGet_0**](JobsApi.md#getJobResultsJobsV1JobsJobIdResultsGet_0) | **GET** /jobs/v1/jobs/{job_id}/results | Get job results (paged) |
| [**getJobStatusJobsV1JobsJobIdGet**](JobsApi.md#getJobStatusJobsV1JobsJobIdGet) | **GET** /jobs/v1/jobs/{job_id} | Get job status |
| [**getJobStatusJobsV1JobsJobIdGet_0**](JobsApi.md#getJobStatusJobsV1JobsJobIdGet_0) | **GET** /jobs/v1/jobs/{job_id} | Get job status |


<a id="createJobJobsV1JobsPost"></a>
# **createJobJobsV1JobsPost**
> JobCreateResponse createJobJobsV1JobsPost(jobCreateRequest, xIdempotencyKey, xAPIKey, authorization)

Create validation job

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.JobsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    JobsApi apiInstance = new JobsApi(defaultClient);
    JobCreateRequest jobCreateRequest = new JobCreateRequest(); // JobCreateRequest | 
    String xIdempotencyKey = "xIdempotencyKey_example"; // String | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      JobCreateResponse result = apiInstance.createJobJobsV1JobsPost(jobCreateRequest, xIdempotencyKey, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling JobsApi#createJobJobsV1JobsPost");
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
| **jobCreateRequest** | [**JobCreateRequest**](JobCreateRequest.md)|  | |
| **xIdempotencyKey** | **String**|  | [optional] |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**JobCreateResponse**](JobCreateResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **201** | Job queued |  -  |
| **400** | Invalid request |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **409** | Idempotent replay |  -  |
| **422** | Validation Error |  -  |

<a id="createJobJobsV1JobsPost_0"></a>
# **createJobJobsV1JobsPost_0**
> JobCreateResponse createJobJobsV1JobsPost_0(jobCreateRequest, xIdempotencyKey, xAPIKey, authorization)

Create validation job

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.JobsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    JobsApi apiInstance = new JobsApi(defaultClient);
    JobCreateRequest jobCreateRequest = new JobCreateRequest(); // JobCreateRequest | 
    String xIdempotencyKey = "xIdempotencyKey_example"; // String | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      JobCreateResponse result = apiInstance.createJobJobsV1JobsPost_0(jobCreateRequest, xIdempotencyKey, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling JobsApi#createJobJobsV1JobsPost_0");
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
| **jobCreateRequest** | [**JobCreateRequest**](JobCreateRequest.md)|  | |
| **xIdempotencyKey** | **String**|  | [optional] |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**JobCreateResponse**](JobCreateResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successful Response |  -  |
| **201** | Job queued |  -  |
| **400** | Invalid request |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **409** | Idempotent replay |  -  |
| **422** | Validation Error |  -  |

<a id="getJobResultsJobsV1JobsJobIdResultsGet"></a>
# **getJobResultsJobsV1JobsJobIdResultsGet**
> JobResultsPage getJobResultsJobsV1JobsJobIdResultsGet(jobId, page, size, xAPIKey, authorization)

Get job results (paged)

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.JobsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    JobsApi apiInstance = new JobsApi(defaultClient);
    String jobId = "jobId_example"; // String | 
    Integer page = 1; // Integer | 
    Integer size = 500; // Integer | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      JobResultsPage result = apiInstance.getJobResultsJobsV1JobsJobIdResultsGet(jobId, page, size, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling JobsApi#getJobResultsJobsV1JobsJobIdResultsGet");
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
| **jobId** | **String**|  | |
| **page** | **Integer**|  | [optional] [default to 1] |
| **size** | **Integer**|  | [optional] [default to 500] |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**JobResultsPage**](JobResultsPage.md)

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

<a id="getJobResultsJobsV1JobsJobIdResultsGet_0"></a>
# **getJobResultsJobsV1JobsJobIdResultsGet_0**
> JobResultsPage getJobResultsJobsV1JobsJobIdResultsGet_0(jobId, page, size, xAPIKey, authorization)

Get job results (paged)

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.JobsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    JobsApi apiInstance = new JobsApi(defaultClient);
    String jobId = "jobId_example"; // String | 
    Integer page = 1; // Integer | 
    Integer size = 500; // Integer | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      JobResultsPage result = apiInstance.getJobResultsJobsV1JobsJobIdResultsGet_0(jobId, page, size, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling JobsApi#getJobResultsJobsV1JobsJobIdResultsGet_0");
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
| **jobId** | **String**|  | |
| **page** | **Integer**|  | [optional] [default to 1] |
| **size** | **Integer**|  | [optional] [default to 500] |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**JobResultsPage**](JobResultsPage.md)

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

<a id="getJobStatusJobsV1JobsJobIdGet"></a>
# **getJobStatusJobsV1JobsJobIdGet**
> JobStatusResponse getJobStatusJobsV1JobsJobIdGet(jobId, xAPIKey, authorization)

Get job status

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.JobsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    JobsApi apiInstance = new JobsApi(defaultClient);
    String jobId = "jobId_example"; // String | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      JobStatusResponse result = apiInstance.getJobStatusJobsV1JobsJobIdGet(jobId, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling JobsApi#getJobStatusJobsV1JobsJobIdGet");
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
| **jobId** | **String**|  | |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**JobStatusResponse**](JobStatusResponse.md)

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

<a id="getJobStatusJobsV1JobsJobIdGet_0"></a>
# **getJobStatusJobsV1JobsJobIdGet_0**
> JobStatusResponse getJobStatusJobsV1JobsJobIdGet_0(jobId, xAPIKey, authorization)

Get job status

### Example
```java
// Import classes:
import com.mailsafepro.ApiClient;
import com.mailsafepro.ApiException;
import com.mailsafepro.Configuration;
import com.mailsafepro.models.*;
import com.mailsafepro.api.JobsApi;

public class Example {
  public static void main(String[] args) {
    ApiClient defaultClient = Configuration.getDefaultApiClient();
    defaultClient.setBasePath("http://localhost");

    JobsApi apiInstance = new JobsApi(defaultClient);
    String jobId = "jobId_example"; // String | 
    String xAPIKey = "xAPIKey_example"; // String | 
    String authorization = "authorization_example"; // String | 
    try {
      JobStatusResponse result = apiInstance.getJobStatusJobsV1JobsJobIdGet_0(jobId, xAPIKey, authorization);
      System.out.println(result);
    } catch (ApiException e) {
      System.err.println("Exception when calling JobsApi#getJobStatusJobsV1JobsJobIdGet_0");
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
| **jobId** | **String**|  | |
| **xAPIKey** | **String**|  | [optional] |
| **authorization** | **String**|  | [optional] |

### Return type

[**JobStatusResponse**](JobStatusResponse.md)

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

