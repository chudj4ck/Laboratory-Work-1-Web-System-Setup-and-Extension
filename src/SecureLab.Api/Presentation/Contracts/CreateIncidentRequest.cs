using System.ComponentModel.DataAnnotations;

namespace SecureLab.Api.Presentation.Contracts;

public record CreateIncidentRequest(
    [Required(ErrorMessage = "Поле Title є обов'язковим.")]
    [StringLength(160, ErrorMessage = "Title не повинен перевищувати 160 символів.")]
    string Title,

    [StringLength(4000, ErrorMessage = "Description не повинен перевищувати 4000 символів.")]
    string? Description,

    [Required(ErrorMessage = "Поле Severity є обов'язковим.")]
    string Severity,

    [Required(ErrorMessage = "Поле Status є обов'язковим.")]
    string Status
);