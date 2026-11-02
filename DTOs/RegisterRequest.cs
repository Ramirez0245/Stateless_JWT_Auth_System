// using System.ComponentModel.DataAnnotations; imports validation attributes such as 
// [Required] and [EmailAddress].
using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

/* This defines the request DTO (Data Transfer Object) used when a client 
registers a new account. It describes the data the API expects and validates 
it before the registration logic uses it. */
public class RegisterRequest
{
    // [Required] rejects a missing or empty value.
    // [EmailAddress] checks that it looks like an email address.
    // [StringLength(255)] limits it to 255 characters.
    [Required, EmailAddress, StringLength(255)]
    public string Email { get; set; } = "";

    // [Required] requires a value. There are no password length 
    // or complexity rules in this class, so those would need to 
    // be added here or enforced elsewhere.
    [Required]
    public string Password { get; set; } = "";
}