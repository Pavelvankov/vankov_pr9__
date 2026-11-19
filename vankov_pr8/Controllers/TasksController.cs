using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using vankov_pr8.Models;

namespace vankov_pr8.Controllers;

[ApiController]
[Route("api/v1/tasks")]
[Authorize]
public class TasksController : ControllerBase
{
    private readonly AppDbContext _context;

    public TasksController(AppDbContext context)
    {
        _context = context;
    }

    public record CreateTaskRequest(string Title, string Description);
    public record UpdateTaskRequest(string Title, string Description, bool IsCompleted);

    [HttpGet]
    public ActionResult GetMyTasks()
    {
        var login = User.Identity?.Name;
        var tasks = _context.Tasks.Where(t => t.OwnerLogin == login).ToList();
        return Ok(tasks);
    }

    [HttpGet("{id}")]
    public ActionResult GetById(int id)
    {
        var task = _context.Tasks.FirstOrDefault(t => t.Id == id);
        if (task == null)
            return NotFound();

        var login = User.Identity?.Name;
        var isAdmin = User.IsInRole("Admin");

        if (task.OwnerLogin != login && !isAdmin)
            return Forbid();

        return Ok(task);
    }

    [HttpPost]
    public ActionResult Create(CreateTaskRequest request)
    {
        var login = User.Identity?.Name ?? "";

        var task = new Models.Task
        {
            Title = request.Title,
            Description = request.Description,
            OwnerLogin = login,
            IsCompleted = false
        };

        _context.Tasks.Add(task);
        _context.SaveChanges();

        return StatusCode(201, task);
    }

    [HttpPut("{id}")]
    public ActionResult Update(int id, UpdateTaskRequest request)
    {
        var task = _context.Tasks.FirstOrDefault(t => t.Id == id);
        if (task == null)
            return NotFound();

        var login = User.Identity?.Name;
        var isAdmin = User.IsInRole("Admin");

        if (task.OwnerLogin != login && !isAdmin)
            return Forbid();

        task.Title = request.Title;
        task.Description = request.Description;
        task.IsCompleted = request.IsCompleted;

        _context.SaveChanges();

        return Ok(task);
    }

    [HttpDelete("{id}")]
    public ActionResult Delete(int id)
    {
        var task = _context.Tasks.FirstOrDefault(t => t.Id == id);
        if (task == null)
            return NotFound();

        var login = User.Identity?.Name;
        var isAdmin = User.IsInRole("Admin");

        if (task.OwnerLogin != login && !isAdmin)
            return Forbid();

        _context.Tasks.Remove(task);
        _context.SaveChanges();

        return NoContent();
    }

    [HttpGet("all")]
    [Authorize(Roles = "Admin")]
    public ActionResult GetAll()
    {
        var tasks = _context.Tasks.ToList();
        return Ok(tasks);
    }
}
