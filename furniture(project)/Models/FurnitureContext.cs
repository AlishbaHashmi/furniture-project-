using furniture_project_.Models;
using Microsoft.EntityFrameworkCore;

namespace furniture_project_.Models
{

    public partial class FurnitureContext : DbContext
    {
        private Category p;

        public FurnitureContext()
        {
        }

        public FurnitureContext(DbContextOptions<FurnitureContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Category> Categories { get; set; }

        public virtual DbSet<Item> Items { get; set; }

        public virtual DbSet<User> Users { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
            => optionsBuilder.UseSqlServer("data source=DESKTOP-E8N2FQC\\SQLEXPRESS;initial catalog=furniture;user id=furniture;password=furni; TrustServerCertificate=True");

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Category>(entity =>
            {
                entity.HasKey(e => e.CatId).HasName("PK__Categories__6A1C8AFA62D0A215");

                entity.Property(e => e.CatName).HasMaxLength(50);
            });

            modelBuilder.Entity<Item>(entity =>
            {
                entity.HasKey(e => e.Id).HasName("PK__Items__3214EC072626D3BA");

                entity.Property(e => e.Name).HasMaxLength(50);

                entity.HasOne(d => d.Cat).WithMany(p => p.Items)
                    .HasForeignKey(d => d.CatId)
                    .HasConstraintName("FK_Items_ToTable");
            });

          

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id).HasName("PK__users__3214EC0781E522BB");

                entity.ToTable("users");

                entity.Property(e => e.Email)
                    .HasMaxLength(100)
                    .IsUnicode(false)
                    .HasColumnName("email");
                entity.Property(e => e.Password)
                    .HasMaxLength(250)
                    .IsUnicode(false)
                    .HasColumnName("password");
                entity.Property(e => e.Username)
                    .HasMaxLength(100)
                    .IsUnicode(false)
                    .HasColumnName("username");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    } 
}
        