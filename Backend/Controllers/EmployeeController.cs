using Backend.Models;
using Backend.Utilities;
using MySql.Data.MySqlClient;
using simpleProjectAPI.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace simpleProjectAPI.Controllers
{
    public class EmployeeController : ApiController
    {
        //Create USERS
        [HttpPost]
        [Route("api/create")]
        public IHttpActionResult CreateAccount([FromBody] Create create)
        {
            if (create == null ||
                string.IsNullOrWhiteSpace(create.id) ||
                string.IsNullOrWhiteSpace(create.username) ||
                string.IsNullOrWhiteSpace(create.password))
                return BadRequest("Invalid data.");

            try
            {
                using (MySqlConnection conn = new MySqlConnection(
                    ConfigurationManager.ConnectionStrings["MySqlConnection"].ConnectionString))
                {
                    conn.Open();

                    // 🔹 Count total users
                    int totalUsers;
                    using (MySqlCommand countCmd = new MySqlCommand("SELECT COUNT(*) FROM users", conn))
                    {
                        totalUsers = Convert.ToInt32(countCmd.ExecuteScalar());
                    }

                    string roleToAssign = "";

                    // 🔥 FIRST ACCOUNT → SuperAdmin
                    if (totalUsers == 0)
                    {
                        roleToAssign = "SuperAdmin";
                    }
                    else
                    {
                        // 🔐 Get role from JWT token
                        var identity = User.Identity as ClaimsIdentity;
                        var currentRole = identity?.FindFirst(ClaimTypes.Role)?.Value;

                        if (string.IsNullOrEmpty(currentRole))
                            return Unauthorized();

                        // ❌ Nobody can manually create SuperAdmin
                        if (create.role == "SuperAdmin")
                            return BadRequest("Cannot manually create SuperAdmin.");

                        // 🔹 Only SuperAdmin can create Admin
                        if (create.role == "Admin")
                        {
                            if (currentRole != "SuperAdmin")
                                return Unauthorized();

                            roleToAssign = "Admin";
                        }
                        else
                        {
                            // Admin & SuperAdmin can create User
                            if (currentRole == "Admin" || currentRole == "SuperAdmin")
                                roleToAssign = "User";
                            else
                                return Unauthorized();
                        }
                    }

                    // 🔹 Check duplicate username
                    using (MySqlCommand checkCmd =
                        new MySqlCommand("SELECT COUNT(*) FROM users WHERE username=@username", conn))
                    {
                        checkCmd.Parameters.AddWithValue("@username", create.username);
                        if (Convert.ToInt32(checkCmd.ExecuteScalar()) > 0)
                            return BadRequest("Username already exists.");
                    }

                    // 🔹 Insert user (NO date_time_created needed)
                    string insertQuery = @"INSERT INTO users
                                   (id, username, password, status, role)
                                   VALUES
                                   (@id, @username, @password, 'Active', @role)";

                    using (MySqlCommand insertCmd = new MySqlCommand(insertQuery, conn))
                    {
                        insertCmd.Parameters.AddWithValue("@id", create.id);
                        insertCmd.Parameters.AddWithValue("@username", create.username);
                        insertCmd.Parameters.AddWithValue("@password",
                            PasswordHasher.Hash(create.password));
                        insertCmd.Parameters.AddWithValue("@role", roleToAssign);

                        insertCmd.ExecuteNonQuery();
                    }

                    return Ok("Account created as " + roleToAssign);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        // Edit Employee data
        [HttpPut]
        [Route("api/employee/{id}", Name = "Update_Employee")]
        public IHttpActionResult UpdateEmployee(string id, [FromBody] Employee employee)
        {
            if (string.IsNullOrEmpty(id))
                return BadRequest("ID is required.");
            try
            {
                using (MySqlConnection conn = new MySqlConnection(
                ConfigurationManager.ConnectionStrings["MySqlConnection"].ConnectionString))
                {
                    conn.Open();
                    string query = @"
                                    UPDATE employee
                                    SET email = @email
                                    WHERE employee_id = @id";
                    using (MySqlCommand cmd = new MySqlCommand(query, conn))
                    {
                        cmd.Parameters.AddWithValue("@id", id);
                        cmd.Parameters.AddWithValue("@email", employee.email);
                        int rowsAffected = cmd.ExecuteNonQuery();
                        if (rowsAffected == 0)
                            return Content(HttpStatusCode.BadRequest, "Invalid data.");
                    }
                }
                return Ok("Successfully updated.");
            }
            catch (Exception ex)
            {
                return Content(
                HttpStatusCode.InternalServerError,
                "Error updating data: " + ex.Message
                );
            }
        }

        // Create new Employee
        [HttpPost]
        [Route("api/employee/create", Name = "Create_Employee")]
        public IHttpActionResult CreateEmployee([FromBody] Employee create)
        {
            // Validate input
            if (create == null ||
                string.IsNullOrWhiteSpace(create.employee_id) ||
                string.IsNullOrWhiteSpace(create.first_name) ||
                string.IsNullOrWhiteSpace(create.last_name) ||
                string.IsNullOrWhiteSpace(create.gender) ||
                string.IsNullOrWhiteSpace(create.email))
            {
                return Content(HttpStatusCode.BadRequest, "Invalid data");
            }

            try
            {
                using (MySqlConnection conn = new MySqlConnection(
                    ConfigurationManager.ConnectionStrings["MySqlConnection"].ConnectionString))
                {
                    conn.Open();

                    // Check if employee already exists
                    string checkQuery = @"SELECT COUNT(*) FROM employee WHERE employee_id = @id";
                    using (MySqlCommand cmd = new MySqlCommand(checkQuery, conn))
                    {
                        cmd.Parameters.AddWithValue("@id", create.employee_id);
                        int count = Convert.ToInt32(cmd.ExecuteScalar());
                        if (count == 1)
                        {
                            return Content(HttpStatusCode.BadRequest, "Employee already exists!");
                        }
                    }

                    // Insert new employee
                    string insertQuery = @"INSERT INTO employee
                                   (employee_id, first_name, last_name, gender, email)
                                   VALUES (@id, @first, @last, @gender, @email)";

                    using (MySqlCommand addCmd = new MySqlCommand(insertQuery, conn))
                    {
                        addCmd.Parameters.AddWithValue("@id", create.employee_id);
                        addCmd.Parameters.AddWithValue("@first", create.first_name);
                        addCmd.Parameters.AddWithValue("@last", create.last_name);
                        addCmd.Parameters.AddWithValue("@gender", create.gender);
                        addCmd.Parameters.AddWithValue("@email", create.email);

                        addCmd.ExecuteNonQuery();
                    }

                    return Ok("Employee created successfully.");
                }
            }
            catch (Exception ex)
            {
                return Content(HttpStatusCode.InternalServerError, ex.Message);
            }
        }

        //get by ID
        [HttpGet]
        [Route("api/employee/info/{id}", Name = "Employee_Info_Id")]
        public IHttpActionResult EmployeeInfoId(string id)
        {
            if (string.IsNullOrEmpty(id))
                return BadRequest("Invalid data.");
            try
            {
                using (MySqlConnection conn = new MySqlConnection(
                ConfigurationManager.ConnectionStrings["MySqlConnection"].ConnectionString))
                {
                    conn.Open();
                    string query = @"SELECT * FROM employee WHERE employee_id = @id";
                    using (MySqlCommand cmd = new MySqlCommand(query, conn))
                    {
                        cmd.Parameters.AddWithValue("@id", id);
                        using (MySqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (!reader.HasRows)
                                return Content(HttpStatusCode.NotFound, "No data.");
                            reader.Read();
                            Employee employee = new Employee
                            {
                                employee_id = reader["employee_id"].ToString(),
                                first_name = reader["first_name"].ToString(),
                                last_name = reader["last_name"].ToString(),
                                gender = reader["gender"].ToString(),
                                email = reader["email"].ToString(),
                            };
                            return Ok(employee);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return Content(HttpStatusCode.InternalServerError, ex.Message);
            }
        }
        // GET EmployeeData
        [HttpGet]
        [Route("api/employee/info", Name = "Employee_Info")]
        public IHttpActionResult EmployeeInfo()
        {
            try
            {
                using (MySqlConnection conn = new MySqlConnection(
                ConfigurationManager.ConnectionStrings["MySqlConnection"].ConnectionString))
                {
                    conn.Open();
                    string query = @"SELECT * FROM employee";
                    using (MySqlCommand cmd = new MySqlCommand(query, conn))
                    {
                        using (MySqlDataReader reader = cmd.ExecuteReader())
                        {
                            if (!reader.HasRows)
                                return NotFound();
                            List<Employee> stats = new List<Employee>();
                            while (reader.Read())
                            {
                                stats.Add(new Employee
                                {
                                    employee_id = reader["employee_id"].ToString(),
                                    first_name = reader["first_name"].ToString(),
                                    last_name = reader["last_name"].ToString(),
                                    gender = reader["gender"].ToString(),
                                    email = reader["email"].ToString(),
                                });
                            }
                            return Ok(stats);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return Content(HttpStatusCode.InternalServerError, ex.Message);
            }
        } 
    }
}
