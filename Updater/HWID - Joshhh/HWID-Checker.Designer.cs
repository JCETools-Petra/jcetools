namespace HWID___Joshhh
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.mainLayout = new System.Windows.Forms.TableLayoutPanel();
            this.statusPanel = new System.Windows.Forms.Panel();
            this.progressBar = new System.Windows.Forms.ProgressBar();
            this.lblStatus = new System.Windows.Forms.Label();
            this.pnlContent = new System.Windows.Forms.Panel();
            this.pnlInvalidUser = new System.Windows.Forms.Panel();
            this.btnBuyAccess = new System.Windows.Forms.Button();
            this.btnDownloadFree = new System.Windows.Forms.Button();
            this.pnlValidUser = new System.Windows.Forms.Panel();
            this.btnDownloadUser = new System.Windows.Forms.Button();
            this.lblWelcomeUser = new System.Windows.Forms.Label();
            this.btnDownloadCustom = new System.Windows.Forms.Button();
            this.mainLayout.SuspendLayout();
            this.statusPanel.SuspendLayout();
            this.pnlContent.SuspendLayout();
            this.pnlInvalidUser.SuspendLayout();
            this.pnlValidUser.SuspendLayout();
            this.SuspendLayout();
            // 
            // mainLayout
            // 
            this.mainLayout.ColumnCount = 1;
            this.mainLayout.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.mainLayout.Controls.Add(this.statusPanel, 0, 2);
            this.mainLayout.Controls.Add(this.pnlContent, 0, 1);
            this.mainLayout.Dock = System.Windows.Forms.DockStyle.Fill;
            this.mainLayout.Location = new System.Drawing.Point(0, 0);
            this.mainLayout.Name = "mainLayout";
            this.mainLayout.RowCount = 3;
            this.mainLayout.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 8F));
            this.mainLayout.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.mainLayout.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 50F));
            this.mainLayout.Size = new System.Drawing.Size(384, 138);
            this.mainLayout.TabIndex = 0;
            // 
            // statusPanel
            // 
            this.statusPanel.Controls.Add(this.progressBar);
            this.statusPanel.Controls.Add(this.lblStatus);
            this.statusPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.statusPanel.Location = new System.Drawing.Point(3, 91);
            this.statusPanel.Name = "statusPanel";
            this.statusPanel.Size = new System.Drawing.Size(378, 44);
            this.statusPanel.TabIndex = 1;
            // 
            // progressBar
            // 
            this.progressBar.Location = new System.Drawing.Point(9, 21);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(360, 10);
            this.progressBar.Style = System.Windows.Forms.ProgressBarStyle.Continuous;
            this.progressBar.TabIndex = 1;
            // 
            // lblStatus
            // 
            this.lblStatus.AutoSize = true;
            this.lblStatus.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblStatus.ForeColor = System.Drawing.Color.WhiteSmoke;
            this.lblStatus.Location = new System.Drawing.Point(6, 3);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(126, 15);
            this.lblStatus.TabIndex = 0;
            this.lblStatus.Text = "Menghubungi server...";
            // 
            // pnlContent
            // 
            this.pnlContent.Controls.Add(this.pnlInvalidUser);
            this.pnlContent.Controls.Add(this.pnlValidUser);
            this.pnlContent.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlContent.Location = new System.Drawing.Point(3, 11);
            this.pnlContent.Name = "pnlContent";
            this.pnlContent.Size = new System.Drawing.Size(378, 74);
            this.pnlContent.TabIndex = 2;
            // 
            // pnlInvalidUser
            // 
            this.pnlInvalidUser.Controls.Add(this.btnBuyAccess);
            this.pnlInvalidUser.Controls.Add(this.btnDownloadFree);
            this.pnlInvalidUser.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlInvalidUser.Location = new System.Drawing.Point(0, 0);
            this.pnlInvalidUser.Name = "pnlInvalidUser";
            this.pnlInvalidUser.Size = new System.Drawing.Size(378, 74);
            this.pnlInvalidUser.TabIndex = 3;
            // 
            // btnBuyAccess
            // 
            this.btnBuyAccess.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.btnBuyAccess.FlatAppearance.BorderSize = 0;
            this.btnBuyAccess.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnBuyAccess.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.btnBuyAccess.ForeColor = System.Drawing.Color.White;
            this.btnBuyAccess.Location = new System.Drawing.Point(20, 25);
            this.btnBuyAccess.Name = "btnBuyAccess";
            this.btnBuyAccess.Size = new System.Drawing.Size(160, 35);
            this.btnBuyAccess.TabIndex = 3;
            this.btnBuyAccess.Text = "Beli Akses Penuh";
            this.btnBuyAccess.UseVisualStyleBackColor = false;
            // 
            // btnDownloadFree
            // 
            this.btnDownloadFree.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(63)))), ((int)(((byte)(63)))), ((int)(((byte)(70)))));
            this.btnDownloadFree.FlatAppearance.BorderSize = 0;
            this.btnDownloadFree.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnDownloadFree.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.btnDownloadFree.ForeColor = System.Drawing.Color.White;
            this.btnDownloadFree.Location = new System.Drawing.Point(198, 25);
            this.btnDownloadFree.Name = "btnDownloadFree";
            this.btnDownloadFree.Size = new System.Drawing.Size(160, 35);
            this.btnDownloadFree.TabIndex = 4;
            this.btnDownloadFree.Text = "Gunakan Versi Gratis";
            this.btnDownloadFree.UseVisualStyleBackColor = false;
            // 
            // pnlValidUser
            // 
            this.pnlValidUser.Controls.Add(this.btnDownloadUser);
            this.pnlValidUser.Controls.Add(this.lblWelcomeUser);
            this.pnlValidUser.Controls.Add(this.btnDownloadCustom);
            this.pnlValidUser.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlValidUser.Location = new System.Drawing.Point(0, 0);
            this.pnlValidUser.Name = "pnlValidUser";
            this.pnlValidUser.Size = new System.Drawing.Size(378, 74);
            this.pnlValidUser.TabIndex = 2;
            // 
            // btnDownloadUser
            // 
            this.btnDownloadUser.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.btnDownloadUser.FlatAppearance.BorderSize = 0;
            this.btnDownloadUser.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnDownloadUser.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.btnDownloadUser.ForeColor = System.Drawing.Color.White;
            this.btnDownloadUser.Location = new System.Drawing.Point(20, 40);
            this.btnDownloadUser.Name = "btnDownloadUser";
            this.btnDownloadUser.Size = new System.Drawing.Size(160, 35);
            this.btnDownloadUser.TabIndex = 0;
            this.btnDownloadUser.Text = "Download File Utama";
            this.btnDownloadUser.UseVisualStyleBackColor = false;
            // 
            // lblWelcomeUser
            // 
            this.lblWelcomeUser.Font = new System.Drawing.Font("Segoe UI", 9.75F);
            this.lblWelcomeUser.ForeColor = System.Drawing.Color.WhiteSmoke;
            this.lblWelcomeUser.Location = new System.Drawing.Point(3, 10);
            this.lblWelcomeUser.Name = "lblWelcomeUser";
            this.lblWelcomeUser.Size = new System.Drawing.Size(372, 23);
            this.lblWelcomeUser.TabIndex = 2;
            this.lblWelcomeUser.Text = "Selamat Datang, Pengguna!";
            this.lblWelcomeUser.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // btnDownloadCustom
            // 
            this.btnDownloadCustom.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(63)))), ((int)(((byte)(63)))), ((int)(((byte)(70)))));
            this.btnDownloadCustom.FlatAppearance.BorderSize = 0;
            this.btnDownloadCustom.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnDownloadCustom.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.btnDownloadCustom.ForeColor = System.Drawing.Color.White;
            this.btnDownloadCustom.Location = new System.Drawing.Point(198, 40);
            this.btnDownloadCustom.Name = "btnDownloadCustom";
            this.btnDownloadCustom.Size = new System.Drawing.Size(160, 35);
            this.btnDownloadCustom.TabIndex = 1;
            this.btnDownloadCustom.Text = "Download File Lain";
            this.btnDownloadCustom.UseVisualStyleBackColor = false;
            // 
            // Form1
            // 
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(45)))), ((int)(((byte)(45)))), ((int)(((byte)(48)))));
            this.ClientSize = new System.Drawing.Size(384, 138);
            this.Controls.Add(this.mainLayout);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "JCE Updater";
            this.mainLayout.ResumeLayout(false);
            this.statusPanel.ResumeLayout(false);
            this.statusPanel.PerformLayout();
            this.pnlContent.ResumeLayout(false);
            this.pnlInvalidUser.ResumeLayout(false);
            this.pnlValidUser.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TableLayoutPanel mainLayout;
        private System.Windows.Forms.Panel statusPanel;
        private System.Windows.Forms.ProgressBar progressBar;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.Panel pnlValidUser;
        private System.Windows.Forms.Button btnDownloadUser;
        private System.Windows.Forms.Button btnDownloadCustom;
        private System.Windows.Forms.Label lblWelcomeUser;
        private System.Windows.Forms.Panel pnlInvalidUser;
        private System.Windows.Forms.Button btnBuyAccess;
        private System.Windows.Forms.Button btnDownloadFree;
        private System.Windows.Forms.Panel pnlContent;
    }
}