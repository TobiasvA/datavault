--create or replace database datavault;
--use datavault;
--create or replace user 'dvload'@'%'
--identified by 'dvload';
create or replace table teilvertrag_hub
        (meta_loaddate timestamp not null,
        meta_recordsource varchar(28) not null,
        meta_jobinstanceid bigint not null,
        meta_hk_teilvertrag_ec char(64) not null,
        mandant smallint(3) unsigned,
        vertrag_ec varchar(32),
        teilvertrag_ec varchar(32),
        constraint pk_teilvertrag_hub primary key (meta_hk_teilvertrag_ec)
);
insert into teilvertrag_hub (
        meta_loaddate,
        meta_recordsource,
        meta_jobinstanceid,
        meta_hk_teilvertrag_ec,
        mandant,
        vertrag_ec,
        teilvertrag_ec)
values (
        timestamp('0000-00-00 00:00:00.0'),
        'SYSTEM',
        0,
        '0000000000000000000000000000',
        null,
        null,
        null
);
--grant select, insert
--on teilvertrag_hub
--to dvload;
create or replace table teilvertrag_hub_eks(
        meta_loaddate timestamp not null,
        meta_recordsource varchar(28) not null,
        meta_jobinstanceid bigint not null,
        meta_hk_teilvertrag char(40) not null,
        meta_hk_teilvertrag_ec char(64) not null,
        meta_hk_teilvertrag_crc char(40) not null,
        meta_teilvertrag_hub_ek char(32) not null,
        constraint pk_teilvertrag_hub_eks primary key (meta_hk_teilvertrag)
);
create or replace index index_teilvertrag_hub_eks_1
on teilvertrag_hub_eks(meta_hk_teilvertrag_ec);
--grant select, insert, update, delete
--on teilvertrag_hub_eks
--to dvload;

