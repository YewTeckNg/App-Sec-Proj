using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebApplication3.Model
{
    public class AuditLog
    {
            [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
            [Key]
            public int Id { get; set; }
            public string UserId { get; set; }
            public string Activity { get; set; }
            public DateTime DateTime { get; set; }
        
    }
}
