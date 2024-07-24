-- start query 1 in stream 0 using template query86.tpl
SELECT   
    SUM(ws_net_paid) AS total_sum,
    i_category,
    i_class,
    GROUPING(i_category) + GROUPING(i_class) AS lochierarchy,
    RANK() OVER (
        PARTITION BY GROUPING(i_category) + GROUPING(i_class),
        CASE WHEN GROUPING(i_class) = 0 THEN i_category END 
        ORDER BY SUM(ws_net_paid) DESC
    ) AS rank_within_parent
FROM
    web_sales,
    date_dim d1,
    item
WHERE
    d1.d_month_seq BETWEEN 1212 AND 1212+11
    AND d1.d_date_sk = ws_sold_date_sk
    AND i_item_sk = ws_item_sk
GROUP BY 
    ROLLUP(i_category, i_class)
ORDER BY
    GROUPING(i_category) + GROUPING(i_class) DESC,
    CASE WHEN GROUPING(i_category) + GROUPING(i_class) = 0 THEN i_category END,
    rank_within_parent
LIMIT 100;

-- end query 1 in stream 0 using template query86.tpl
