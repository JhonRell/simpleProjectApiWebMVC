using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Frontend.Models
{
    public class Employee
    {
        public string employee_id { get; set; }
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string gender { get; set; }
        public string email { get; set; }
    }

    public class EmployeeHolder
    {
        public IEnumerable<Employee> employeeHolder { get; set; }
    }
}