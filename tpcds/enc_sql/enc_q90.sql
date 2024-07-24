-- start query 1 in stream 0 using template query90.tpl
select  *
-- select  amc/pmc am_pm_ratio
 from ( select count(*) amc
       from web_sales, household_demographics , time_dim, web_page
       where ws_sold_time_sk = time_dim.t_time_sk
         and ws_ship_hdemo_sk = household_demographics.hd_demo_sk
         and ws_web_page_sk = web_page.wp_web_page_sk
         and time_dim.t_hour between '6' and '7'
         and household_demographics.hd_dep_count = '8'
         and web_page.wp_char_count between '5000' and '5200') at,
      ( select count(*) pmc
       from web_sales, household_demographics , time_dim, web_page
       where ws_sold_time_sk = time_dim.t_time_sk
         and ws_ship_hdemo_sk = household_demographics.hd_demo_sk
         and ws_web_page_sk = web_page.wp_web_page_sk
         and time_dim.t_hour between '14' and '15'
         and household_demographics.hd_dep_count = '8'
         and web_page.wp_char_count between '5000' and '5200') pt
--  order by am_pm_ratio
 limit 100;

-- end query 1 in stream 0 using template query90.tpl
