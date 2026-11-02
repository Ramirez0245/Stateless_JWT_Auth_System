using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

public class LoginRequest
{
    [Required, StringLength(255)]
    public string Email { get; set; } = "";

    [Required]
    public string Password { get; set; } = "";
}