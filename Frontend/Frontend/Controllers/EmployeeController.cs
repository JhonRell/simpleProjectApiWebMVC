using Frontend.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace Frontend.Controllers
{
    public class EmployeeController : Controller
    {

        //Edit Email
        [HttpPut]
        public ActionResult UpdateData(Employee employee)
        {
            if (employee == null || string.IsNullOrEmpty(employee.employee_id))
            {
                return Content("Invalid employee data.", "text/plain", Encoding.UTF8);
            }

            try
            {
                string apiUrl =
                    ConfigurationManager.AppSettings["BackendApiUrl"]
                    + "api/employee/"
                    + employee.employee_id;

                string jsonData =
                    Newtonsoft.Json.JsonConvert.SerializeObject(employee);

                byte[] data = Encoding.UTF8.GetBytes(jsonData);

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(apiUrl);

                req.Method = "PUT";
                req.ContentType = "application/json";
                req.Accept = "application/json";
                req.ContentLength = data.Length;

                using (Stream stream = req.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (var reader = new StreamReader(res.GetResponseStream()))
                {
                    string msg = reader.ReadToEnd().Trim('"');
                    return Content(msg, "text/plain", Encoding.UTF8);
                }
            }
            catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    using (HttpWebResponse res = (HttpWebResponse)ex.Response)
                    using (Stream receiveStream = res.GetResponseStream())
                    using (StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8))
                    {
                        string msg = readStream.ReadToEnd();

                        // Return same status code as backend API
                        Response.StatusCode = (int)res.StatusCode;

                        return Content(msg, "text/plain");
                    }
                }

                Response.StatusCode = 500;
                return Content("Error connecting to API.");
            }
        }

        // Add new employee 
        [HttpPost]
        public ActionResult CreateData(Employee employee)
        {
            if (employee == null)
            {
                return Content("Invalid employee data.", "text/plain", Encoding.UTF8);
            }

            try
            {
                string apiUrl = ConfigurationManager.AppSettings["BackendApiUrl"] + "api/employee/create";

                string jsonData = Newtonsoft.Json.JsonConvert.SerializeObject(employee);
                byte[] data = Encoding.UTF8.GetBytes(jsonData);

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(apiUrl);
                req.Method = "POST";
                req.ContentType = "application/json";
                req.Accept = "application/json";
                req.ContentLength = data.Length;

                using (Stream stream = req.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (var reader = new StreamReader(res.GetResponseStream()))
                {
                    string msg = reader.ReadToEnd().Trim('"');

                    // Forward success response as 200
                    return Content(msg, "text/plain", Encoding.UTF8);
                }
            }
            catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    using (HttpWebResponse res = (HttpWebResponse)ex.Response)
                    using (Stream receiveStream = res.GetResponseStream())
                    using (StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8))
                    {
                        string msg = readStream.ReadToEnd().Trim('"');

                        // Return same status code as backend API
                        Response.StatusCode = (int)res.StatusCode;
                        return Content(msg, "text/plain");
                    }
                }

                Response.StatusCode = 500;
                return Content("Error connecting to API.");
            }
        }

        //get by id
        public ActionResult EmployeeDetails(string id)
        {
            EmployeeHolder employeeDetails = new EmployeeHolder();
            employeeDetails.employeeHolder = Employee(id);
            return View("EmployeeDetails", employeeDetails);
        }
        //get by ID
        public IEnumerable<Employee> Employee(string id)
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri(
                ConfigurationManager.AppSettings["BackendApiUrl"] + "api/employee/");
                var responseTask = httpClient.GetAsync("info/" + id);
                responseTask.Wait();
                var response = responseTask.Result;
                if (!response.IsSuccessStatusCode)
                {
                    ViewBag.Data = "An error has occured";
                    return Enumerable.Empty<Employee>();
                }
                var readTask = response.Content.ReadAsAsync<Employee>();
                readTask.Wait();
                var employee = readTask.Result;
                return new List<Employee> { employee };
            }
        }

        // GET: Employee
        public ActionResult EmployeeData()
        {
            EmployeeHolder employeeData = new EmployeeHolder();
            employeeData.employeeHolder = Employee();
            return View("EmployeeData", employeeData);
        }

        //get all employee data
        public IEnumerable<Employee> Employee()
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri(
                ConfigurationManager.AppSettings["BackendApiUrl"] + "api/employee/");
                var responseTask = httpClient.GetAsync("info");
                responseTask.Wait();
                var response = responseTask.Result;
                if (!response.IsSuccessStatusCode)
                {
                    ViewBag.Data = "An error has occured";
                    return Enumerable.Empty<Employee>();
                }
                var readTask = response.Content.ReadAsAsync<List<Employee>>();
                readTask.Wait();
                return readTask.Result;
            }
        }
    }
}