create table [dm_aou].[dbo].[metadata] (
  rid       bigint not null identity(1,1) primary key
, ts        datetime default getdate() not null
, tag       nvarchar(max) not null
, details   nvarchar(max) null
);

