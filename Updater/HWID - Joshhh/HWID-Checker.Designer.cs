namespace HWID___Joshhh
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.pnlHeader = new System.Windows.Forms.Panel();
            this.lblTitle = new System.Windows.Forms.Label();
            this.btnMinimize = new System.Windows.Forms.Button();
            this.btnClose = new System.Windows.Forms.Button();
            this.pnlStatus = new System.Windows.Forms.Panel();
            this.lblVersion = new System.Windows.Forms.Label();
            this.lblStatus = new System.Windows.Forms.Label();
            this.progressBar = new System.Windows.Forms.ProgressBar();
            this.pnlMain = new System.Windows.Forms.Panel();
            this.pnlValidUser = new System.Windows.Forms.Panel();
            this.pnlNewsContainer = new System.Windows.Forms.Panel();
            this.rtbNews = new System.Windows.Forms.RichTextBox();
            this.lblNewsHeader = new System.Windows.Forms.Label();
            this.pnlActionButtons = new System.Windows.Forms.Panel();
            this.btnDownloadUser = new System.Windows.Forms.Button();
            this.btnDownloadCustom = new System.Windows.Forms.Button();
            this.pnlUserInfo = new System.Windows.Forms.Panel();
            this.lblExpiryDate = new System.Windows.Forms.Label();
            this.lblWelcomeUser = new System.Windows.Forms.Label();
            this.pnlInvalidUser = new System.Windows.Forms.Panel();
            this.label1 = new System.Windows.Forms.Label();
            this.btnBuyAccess = new System.Windows.Forms.Button();
            this.btnDownloadFree = new System.Windows.Forms.Button();
            this.pnlHeader.SuspendLayout();
            this.pnlStatus.SuspendLayout();
            this.pnlMain.SuspendLayout();
            this.pnlValidUser.SuspendLayout();
            this.pnlNewsContainer.SuspendLayout();
            this.pnlActionButtons.SuspendLayout();
            this.pnlUserInfo.SuspendLayout();
            this.pnlInvalidUser.SuspendLayout();
            this.SuspendLayout();
            // 
            // pnlHeader
            // 
            this.pnlHeader.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(30)))), ((int)(((byte)(30)))), ((int)(((byte)(30)))));
            this.pnlHeader.Controls.Add(this.lblTitle);
            this.pnlHeader.Controls.Add(this.btnMinimize);
            this.pnlHeader.Controls.Add(this.btnClose);
            this.pnlHeader.Dock = System.Windows.Forms.DockStyle.Top;
            this.pnlHeader.Location = new System.Drawing.Point(0, 0);
            this.pnlHeader.Name = "pnlHeader";
            this.pnlHeader.Size = new System.Drawing.Size(700, 40);
            this.pnlHeader.TabIndex = 0;
            this.pnlHeader.MouseDown += new System.Windows.Forms.MouseEventHandler(this.pnlHeader_MouseDown);
            // 
            // lblTitle
            // 
            this.lblTitle.AutoSize = true;
            this.lblTitle.Font = new System.Drawing.Font("Segoe UI", 11.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblTitle.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.lblTitle.Location = new System.Drawing.Point(12, 10);
            this.lblTitle.Name = "lblTitle";
            this.lblTitle.Size = new System.Drawing.Size(94, 20);
            this.lblTitle.TabIndex = 2;
            this.lblTitle.Text = "JCE Updater";
            this.lblTitle.MouseDown += new System.Windows.Forms.MouseEventHandler(this.pnlHeader_MouseDown);
            // 
            // btnMinimize
            // 
            this.btnMinimize.Dock = System.Windows.Forms.DockStyle.Right;
            this.btnMinimize.FlatAppearance.BorderSize = 0;
            this.btnMinimize.FlatAppearance.MouseOverBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(63)))), ((int)(((byte)(63)))), ((int)(((byte)(70)))));
            this.btnMinimize.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnMinimize.Font = new System.Drawing.Font("Marlett", 9F);
            this.btnMinimize.ForeColor = System.Drawing.Color.Gray;
            this.btnMinimize.Location = new System.Drawing.Point(620, 0);
            this.btnMinimize.Name = "btnMinimize";
            this.btnMinimize.Size = new System.Drawing.Size(40, 40);
            this.btnMinimize.TabIndex = 1;
            this.btnMinimize.Text = "0";
            this.btnMinimize.UseVisualStyleBackColor = true;
            this.btnMinimize.Click += new System.EventHandler(this.btnMinimize_Click);
            // 
            // btnClose
            // 
            this.btnClose.Dock = System.Windows.Forms.DockStyle.Right;
            this.btnClose.FlatAppearance.BorderSize = 0;
            this.btnClose.FlatAppearance.MouseOverBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(232)))), ((int)(((byte)(17)))), ((int)(((byte)(35)))));
            this.btnClose.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnClose.Font = new System.Drawing.Font("Marlett", 9F);
            this.btnClose.ForeColor = System.Drawing.Color.Gray;
            this.btnClose.Location = new System.Drawing.Point(660, 0);
            this.btnClose.Name = "btnClose";
            this.btnClose.Size = new System.Drawing.Size(40, 40);
            this.btnClose.TabIndex = 0;
            this.btnClose.Text = "r";
            this.btnClose.UseVisualStyleBackColor = true;
            this.btnClose.Click += new System.EventHandler(this.btnClose_Click);
            // 
            // pnlStatus
            // 
            this.pnlStatus.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.pnlStatus.Controls.Add(this.lblVersion);
            this.pnlStatus.Controls.Add(this.lblStatus);
            this.pnlStatus.Controls.Add(this.progressBar);
            this.pnlStatus.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.pnlStatus.Location = new System.Drawing.Point(0, 420);
            this.pnlStatus.Name = "pnlStatus";
            this.pnlStatus.Size = new System.Drawing.Size(700, 30);
            this.pnlStatus.TabIndex = 2;
            // 
            // lblVersion
            // 
            this.lblVersion.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.lblVersion.AutoSize = true;
            this.lblVersion.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblVersion.ForeColor = System.Drawing.Color.White;
            this.lblVersion.Location = new System.Drawing.Point(617, 7);
            this.lblVersion.Name = "lblVersion";
            this.lblVersion.Size = new System.Drawing.Size(50, 13);
            this.lblVersion.TabIndex = 2;
            this.lblVersion.Text = "v.2.0 Pro";
            // 
            // lblStatus
            // 
            this.lblStatus.AutoSize = true;
            this.lblStatus.Font = new System.Drawing.Font("Segoe UI Semibold", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblStatus.ForeColor = System.Drawing.Color.White;
            this.lblStatus.Location = new System.Drawing.Point(10, 7);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(75, 15);
            this.lblStatus.TabIndex = 0;
            this.lblStatus.Text = "Menunggu...";
            // 
            // progressBar
            // 
            this.progressBar.Dock = System.Windows.Forms.DockStyle.Top;
            this.progressBar.Location = new System.Drawing.Point(0, 0);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(700, 3);
            this.progressBar.Style = System.Windows.Forms.ProgressBarStyle.Continuous;
            this.progressBar.TabIndex = 1;
            this.progressBar.Visible = false;
            // 
            // pnlMain
            // 
            this.pnlMain.Controls.Add(this.pnlValidUser);
            this.pnlMain.Controls.Add(this.pnlInvalidUser);
            this.pnlMain.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlMain.Location = new System.Drawing.Point(0, 40);
            this.pnlMain.Name = "pnlMain";
            this.pnlMain.Size = new System.Drawing.Size(700, 380);
            this.pnlMain.TabIndex = 3;
            // 
            // pnlValidUser
            // 
            this.pnlValidUser.Controls.Add(this.pnlNewsContainer);
            this.pnlValidUser.Controls.Add(this.pnlActionButtons);
            this.pnlValidUser.Controls.Add(this.pnlUserInfo);
            this.pnlValidUser.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlValidUser.Location = new System.Drawing.Point(0, 380);
            this.pnlValidUser.Name = "pnlValidUser";
            this.pnlValidUser.Padding = new System.Windows.Forms.Padding(20);
            this.pnlValidUser.Size = new System.Drawing.Size(700, 0);
            this.pnlValidUser.TabIndex = 2;
            // 
            // pnlNewsContainer
            // 
            this.pnlNewsContainer.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(35)))), ((int)(((byte)(35)))), ((int)(((byte)(35)))));
            this.pnlNewsContainer.Controls.Add(this.rtbNews);
            this.pnlNewsContainer.Controls.Add(this.lblNewsHeader);
            this.pnlNewsContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlNewsContainer.Location = new System.Drawing.Point(20, 95);
            this.pnlNewsContainer.Name = "pnlNewsContainer";
            this.pnlNewsContainer.Padding = new System.Windows.Forms.Padding(10);
            this.pnlNewsContainer.Size = new System.Drawing.Size(660, 0);
            this.pnlNewsContainer.TabIndex = 5;
            // 
            // rtbNews
            // 
            this.rtbNews.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(40)))), ((int)(((byte)(40)))), ((int)(((byte)(40)))));
            this.rtbNews.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.rtbNews.Dock = System.Windows.Forms.DockStyle.Fill;
            this.rtbNews.Font = new System.Drawing.Font("Consolas", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rtbNews.ForeColor = System.Drawing.Color.LightGray;
            this.rtbNews.Location = new System.Drawing.Point(10, 35);
            this.rtbNews.Name = "rtbNews";
            this.rtbNews.ReadOnly = true;
            this.rtbNews.Size = new System.Drawing.Size(640, 0);
            this.rtbNews.TabIndex = 1;
            this.rtbNews.Text = "System Initialized.\nMenunggu Server News...\n\n[INFO] Auto-Update system active.\n[I" +
    "NFO] HWID Protection active.";
            // 
            // lblNewsHeader
            // 
            this.lblNewsHeader.Dock = System.Windows.Forms.DockStyle.Top;
            this.lblNewsHeader.Font = new System.Drawing.Font("Segoe UI", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblNewsHeader.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.lblNewsHeader.Location = new System.Drawing.Point(10, 10);
            this.lblNewsHeader.Name = "lblNewsHeader";
            this.lblNewsHeader.Size = new System.Drawing.Size(640, 25);
            this.lblNewsHeader.TabIndex = 0;
            this.lblNewsHeader.Text = "SERVER NEWS / CHANGELOG";
            // 
            // pnlActionButtons
            // 
            this.pnlActionButtons.Controls.Add(this.btnDownloadUser);
            this.pnlActionButtons.Controls.Add(this.btnDownloadCustom);
            this.pnlActionButtons.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.pnlActionButtons.Location = new System.Drawing.Point(20, -80);
            this.pnlActionButtons.Name = "pnlActionButtons";
            this.pnlActionButtons.Padding = new System.Windows.Forms.Padding(0, 10, 0, 0);
            this.pnlActionButtons.Size = new System.Drawing.Size(660, 60);
            this.pnlActionButtons.TabIndex = 4;
            // 
            // btnDownloadUser
            // 
            this.btnDownloadUser.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.btnDownloadUser.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnDownloadUser.Dock = System.Windows.Forms.DockStyle.Right;
            this.btnDownloadUser.FlatAppearance.BorderSize = 0;
            this.btnDownloadUser.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnDownloadUser.Font = new System.Drawing.Font("Segoe UI", 11F, System.Drawing.FontStyle.Bold);
            this.btnDownloadUser.ForeColor = System.Drawing.Color.White;
            this.btnDownloadUser.Location = new System.Drawing.Point(440, 10);
            this.btnDownloadUser.Name = "btnDownloadUser";
            this.btnDownloadUser.Size = new System.Drawing.Size(220, 50);
            this.btnDownloadUser.TabIndex = 0;
            this.btnDownloadUser.Text = "Download Custom Cheat";
            this.btnDownloadUser.UseVisualStyleBackColor = false;
            // 
            // btnDownloadCustom
            // 
            this.btnDownloadCustom.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(50)))), ((int)(((byte)(50)))), ((int)(((byte)(50)))));
            this.btnDownloadCustom.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnDownloadCustom.Dock = System.Windows.Forms.DockStyle.Left;
            this.btnDownloadCustom.FlatAppearance.BorderSize = 0;
            this.btnDownloadCustom.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnDownloadCustom.Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold);
            this.btnDownloadCustom.ForeColor = System.Drawing.Color.LightGray;
            this.btnDownloadCustom.Location = new System.Drawing.Point(0, 10);
            this.btnDownloadCustom.Name = "btnDownloadCustom";
            this.btnDownloadCustom.Size = new System.Drawing.Size(180, 50);
            this.btnDownloadCustom.TabIndex = 1;
            this.btnDownloadCustom.Text = "Download Extra File";
            this.btnDownloadCustom.UseVisualStyleBackColor = false;
            // 
            // pnlUserInfo
            // 
            this.pnlUserInfo.Controls.Add(this.lblExpiryDate);
            this.pnlUserInfo.Controls.Add(this.lblWelcomeUser);
            this.pnlUserInfo.Dock = System.Windows.Forms.DockStyle.Top;
            this.pnlUserInfo.Location = new System.Drawing.Point(20, 20);
            this.pnlUserInfo.Name = "pnlUserInfo";
            this.pnlUserInfo.Size = new System.Drawing.Size(660, 75);
            this.pnlUserInfo.TabIndex = 3;
            // 
            // lblExpiryDate
            // 
            this.lblExpiryDate.AutoSize = true;
            this.lblExpiryDate.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.lblExpiryDate.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(100)))), ((int)(((byte)(255)))), ((int)(((byte)(100)))));
            this.lblExpiryDate.Location = new System.Drawing.Point(3, 38);
            this.lblExpiryDate.Name = "lblExpiryDate";
            this.lblExpiryDate.Size = new System.Drawing.Size(125, 19);
            this.lblExpiryDate.TabIndex = 3;
            this.lblExpiryDate.Text = "License: Checking...";
            // 
            // lblWelcomeUser
            // 
            this.lblWelcomeUser.AutoSize = true;
            this.lblWelcomeUser.Font = new System.Drawing.Font("Segoe UI", 20.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblWelcomeUser.ForeColor = System.Drawing.Color.White;
            this.lblWelcomeUser.Location = new System.Drawing.Point(-3, 0);
            this.lblWelcomeUser.Name = "lblWelcomeUser";
            this.lblWelcomeUser.Size = new System.Drawing.Size(231, 37);
            this.lblWelcomeUser.TabIndex = 2;
            this.lblWelcomeUser.Text = "Selamat Datang!";
            // 
            // pnlInvalidUser
            // 
            this.pnlInvalidUser.Controls.Add(this.label1);
            this.pnlInvalidUser.Controls.Add(this.btnBuyAccess);
            this.pnlInvalidUser.Controls.Add(this.btnDownloadFree);
            this.pnlInvalidUser.Dock = System.Windows.Forms.DockStyle.Top;
            this.pnlInvalidUser.Location = new System.Drawing.Point(0, 0);
            this.pnlInvalidUser.Name = "pnlInvalidUser";
            this.pnlInvalidUser.Size = new System.Drawing.Size(700, 380);
            this.pnlInvalidUser.TabIndex = 3;
            this.pnlInvalidUser.Visible = false;
            // 
            // label1
            // 
            this.label1.Dock = System.Windows.Forms.DockStyle.Top;
            this.label1.Font = new System.Drawing.Font("Segoe UI", 14F);
            this.label1.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(100)))), ((int)(((byte)(100)))));
            this.label1.Location = new System.Drawing.Point(0, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(700, 130);
            this.label1.TabIndex = 5;
            this.label1.Text = "Akses Ditolak / HWID Tidak Terdaftar\r\nSilakan beli akses untuk melanjutkan.";
            this.label1.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            // 
            // btnBuyAccess
            // 
            this.btnBuyAccess.Anchor = System.Windows.Forms.AnchorStyles.Top;
            this.btnBuyAccess.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(122)))), ((int)(((byte)(204)))));
            this.btnBuyAccess.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnBuyAccess.FlatAppearance.BorderSize = 0;
            this.btnBuyAccess.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnBuyAccess.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold);
            this.btnBuyAccess.ForeColor = System.Drawing.Color.White;
            this.btnBuyAccess.Location = new System.Drawing.Point(225, 150);
            this.btnBuyAccess.Name = "btnBuyAccess";
            this.btnBuyAccess.Size = new System.Drawing.Size(250, 50);
            this.btnBuyAccess.TabIndex = 3;
            this.btnBuyAccess.Text = "BELI AKSES VIP";
            this.btnBuyAccess.UseVisualStyleBackColor = false;
            // 
            // btnDownloadFree
            // 
            this.btnDownloadFree.Anchor = System.Windows.Forms.AnchorStyles.Top;
            this.btnDownloadFree.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(60)))), ((int)(((byte)(60)))), ((int)(((byte)(60)))));
            this.btnDownloadFree.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnDownloadFree.FlatAppearance.BorderSize = 0;
            this.btnDownloadFree.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnDownloadFree.Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold);
            this.btnDownloadFree.ForeColor = System.Drawing.Color.White;
            this.btnDownloadFree.Location = new System.Drawing.Point(225, 220);
            this.btnDownloadFree.Name = "btnDownloadFree";
            this.btnDownloadFree.Size = new System.Drawing.Size(250, 40);
            this.btnDownloadFree.TabIndex = 4;
            this.btnDownloadFree.Text = "Coba Versi Gratis";
            this.btnDownloadFree.UseVisualStyleBackColor = false;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(25)))), ((int)(((byte)(25)))), ((int)(((byte)(25)))));
            this.ClientSize = new System.Drawing.Size(700, 450);
            this.Controls.Add(this.pnlMain);
            this.Controls.Add(this.pnlStatus);
            this.Controls.Add(this.pnlHeader);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "JCE Updater";
            this.pnlHeader.ResumeLayout(false);
            this.pnlHeader.PerformLayout();
            this.pnlStatus.ResumeLayout(false);
            this.pnlStatus.PerformLayout();
            this.pnlMain.ResumeLayout(false);
            this.pnlValidUser.ResumeLayout(false);
            this.pnlNewsContainer.ResumeLayout(false);
            this.pnlActionButtons.ResumeLayout(false);
            this.pnlUserInfo.ResumeLayout(false);
            this.pnlUserInfo.PerformLayout();
            this.pnlInvalidUser.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Panel pnlHeader;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.Button btnMinimize;
        private System.Windows.Forms.Label lblTitle;
        private System.Windows.Forms.Panel pnlStatus;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.ProgressBar progressBar;
        private System.Windows.Forms.Panel pnlMain;
        private System.Windows.Forms.Panel pnlValidUser;
        private System.Windows.Forms.Button btnDownloadUser;
        private System.Windows.Forms.Button btnDownloadCustom;
        private System.Windows.Forms.Label lblWelcomeUser;
        private System.Windows.Forms.Panel pnlInvalidUser;
        private System.Windows.Forms.Button btnBuyAccess;
        private System.Windows.Forms.Button btnDownloadFree;
        private System.Windows.Forms.Panel pnlUserInfo;
        private System.Windows.Forms.Label lblExpiryDate;
        private System.Windows.Forms.Panel pnlActionButtons;
        private System.Windows.Forms.Panel pnlNewsContainer;
        private System.Windows.Forms.Label lblNewsHeader;
        private System.Windows.Forms.RichTextBox rtbNews;
        private System.Windows.Forms.Label lblVersion;
        private System.Windows.Forms.Label label1;
    }
}