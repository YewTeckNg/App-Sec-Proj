﻿using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace WebApplication3.Model
{
    public class PasswordHistory
    {
            [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
            [Key]
            public int Id { get; set; }
            public string userId { get; set; } = string.Empty;
            public string passwordHash { get; set; } = string.Empty;
      
    }
}
