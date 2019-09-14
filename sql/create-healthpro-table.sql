CREATE TABLE [dm_aou].[dbo].[healthpro] (
	[PMI ID] NVARCHAR(64) NULL, 
	[Biobank ID] NVARCHAR(64) NULL, 
	[Last Name] NVARCHAR(256) NULL, 
	[First Name] NVARCHAR(256) NULL, 
	[Date of Birth] DATE NULL, 
	[Language] NVARCHAR(32) NULL, 
	[Language of General Consent] NVARCHAR(32) NULL,
  [Participant Status] NVARCHAR(28) NULL,
	[General Consent Status] NVARCHAR(2) NULL, 
	[General Consent Date] DATE NULL, 
	[EHR Consent Status] NVARCHAR(2) NULL, 
	[EHR Consent Date] DATE NULL, 
	[CABoR Consent Status] NVARCHAR(2) NULL, 
	[CABoR Consent Date] DATE NULL, 
	[Withdrawal Status] NVARCHAR(2) NULL, 
	[Withdrawal Reason] NVARCHAR(256) NULL,
	[Withdrawal Date] DATE NULL, 
	[Street Address] NVARCHAR(256) NULL, 
	[Street Address2] NVARCHAR(256) NULL,
	[City] NVARCHAR(128) NULL, 
	[State] NVARCHAR(128) NULL, 
	[ZIP] NVARCHAR(32) NULL, 
	[Email] NVARCHAR(256) NULL, 
	[Phone] NVARCHAR(32) NULL, 
	[Sex] NVARCHAR(32) NULL, 
	[Gender Identity] NVARCHAR(32) NULL, 
	[Race/Ethnicity] NVARCHAR(64) NULL, 
	[Education] NVARCHAR(128) NULL, 
	[Required PPI Surveys Complete] NVARCHAR(2) NULL, 
	[Completed Surveys] NVARCHAR(2) NULL, 
	[Basics PPI Survey Complete] NVARCHAR(2) NULL, 
	[Basics PPI Survey Completion Date] DATE NULL, 
	[Health PPI Survey Complete] NVARCHAR(2) NULL, 
	[Health PPI Survey Completion Date] DATE NULL, 
	[Lifestyle PPI Survey Complete] NVARCHAR(2) NULL, 
	[Lifestyle PPI Survey Completion Date] DATE NULL, 
	[Hist PPI Survey Complete] NVARCHAR(2) NULL, 
	[Hist PPI Survey Completion Date] DATE NULL, 
	[Meds PPI Survey Complete] NVARCHAR(2) NULL, 
	[Meds PPI Survey Completion Date] DATE NULL, 
	[Family PPI Survey Complete] NVARCHAR(2) NULL, 
	[Family PPI Survey Completion Date] DATE NULL, 
	[Access PPI Survey Complete] NVARCHAR(2) NULL, 
	[Access PPI Survey Completion Date] DATE NULL, 
	[Physical Measurements Status] NVARCHAR(2) NULL, 
	[Physical Measurements Completion Date] DATE NULL, 
  [Physical Measurements Site] NVARCHAR(50) NULL,
  [Paired Site] NVARCHAR(50) NULL,
  [Paired Organization] NVARCHAR(50) NULL,
	[Samples for DNA Received] NVARCHAR(2) NULL, 
	[Biospecimens] NVARCHAR(10) NULL, 
	[8 mL SST Collected] NVARCHAR(2) NULL, 
	[8 mL SST Collection Date] DATE NULL, 
	[8 mL PST Collected] NVARCHAR(2) NULL, 
	[8 mL PST Collection Date] DATE NULL, 
	[4 mL Na-Hep Collected] NVARCHAR(2) NULL, 
	[4 mL Na-Hep Collection Date] DATE NULL, 
	[4 mL EDTA Collected] NVARCHAR(2) NULL, 
	[4 mL EDTA Collection Date] DATE NULL, 
	[1st 10 mL EDTA Collected] NVARCHAR(2) NULL, 
	[1st 10 mL EDTA Collection Date] DATE NULL, 
	[2nd 10 mL EDTA Collected] NVARCHAR(2) NULL, 
	[2nd 10 mL EDTA Collection Date] DATE NULL, 
	[Urine 10 mL Collected] NVARCHAR(2) NULL, 
	[Urine 10 mL Collection Date] DATE NULL, 
	[Saliva Collected] NVARCHAR(2) NULL, 
	[Saliva Collection Date] DATE NULL,
  [Biospecimens Site] NVARCHAR(50) NULL
,[2 mL EDTA Collected] NVARCHAR(2) NULL
,[2 mL EDTA Collection Date] DATE NULL
,[Cell-Free DNA Collected] NVARCHAR(2) NULL
,[Cell-Free DNA Collection Date] DATE NULL
,[Paxgene RNA Collected] NVARCHAR(2) NULL
,[Paxgene RNA Collection Date] DATE NULL
,[Urine 90 mL Collected] NVARCHAR(2) NULL
,[Urine 90 mL Collection Date] DATE NULL
,[DV-only EHR Sharing Status] NVARCHAR(2) NULL
,[DV-only EHR Sharing Date] DATE NULL
,[Login Phone] NVARCHAR(32) NULL
)

