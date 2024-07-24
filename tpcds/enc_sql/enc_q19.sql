-- start query 1 in stream 0 using template query19.tpl
select  i_brand_id brand_id, i_brand brand, i_manufact_id, i_manufact,
 	sum(ss_ext_sales_price) ext_price
 from date_dim, store_sales, item,customer,customer_address,store
 where d_date_sk = ss_sold_date_sk
   and ss_item_sk = i_item_sk
   and i_manager_id=enc_int4_encrypt('7')
   and d_moy=enc_int4_encrypt('11')
   and d_year=enc_int4_encrypt('1999')
   and ss_customer_sk = c_customer_sk
   and c_current_addr_sk = ca_address_sk
   and substring(ca_zip,enc_int4_encrypt('1'),enc_int4_encrypt('5')) <> substring(s_zip,enc_int4_encrypt('1'),enc_int4_encrypt('5')) 
   and ss_store_sk = s_store_sk
 group by i_brand
      ,i_brand_id
      ,i_manufact_id
      ,i_manufact
 order by ext_price desc
         ,i_brand
         ,i_brand_id
         ,i_manufact_id
         ,i_manufact
limit 100 ;

-- end query 1 in stream 0 using template query19.tpl
