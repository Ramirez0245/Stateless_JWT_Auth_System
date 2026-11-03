using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

public class RefreshTokenRequest
{
    [Required, StringLength(256)]
    public string RefreshToken { get; set; } = "";
}