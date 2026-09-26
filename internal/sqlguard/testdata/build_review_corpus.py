"""Rebuild the shared, declarative PostgreSQL differential test cases."""
import json
from pathlib import Path
cases=[]
def safe(name,sql,uses,ordered=False):
    cases.append(dict(name=name,sql=sql,allowed=True,columns=uses,ordered=ordered))
def deny(name,sql,tier):
    cases.append(dict(name=name,sql=sql,allowed=False,denial=tier))
safe('join/on','SELECT a.id,b.k FROM a JOIN b ON a.id=b.id ORDER BY a.id',{'a':['id'],'b':['id','k']},True)
for join in ['INNER','LEFT','RIGHT','FULL']:
    safe('join/'+join.lower()+'_using','SELECT id FROM a '+join+' JOIN b USING(id) ORDER BY id',{'a':['id'],'b':['id']},True)
    safe('coercion/'+join.lower()+'_using_arithmetic','SELECT id+2147483647 AS n FROM a '+join+' JOIN b USING(id) ORDER BY id',{'a':['id'],'b':['id']},True)
safe('join/using_alias','SELECT u.id FROM a JOIN b USING(id) AS u ORDER BY u.id',{'a':['id'],'b':['id']},True)
safe('join/whole_join_alias','SELECT j.id FROM (a FULL JOIN b USING(id)) AS j ORDER BY j.id',{'a':['id'],'b':['id']},True)
safe('join/positional_alias','SELECT j.key FROM (a JOIN b USING(id)) AS j(key) ORDER BY j.key',{'a':['id'],'b':['id']},True)
safe('join/nested_using','SELECT id FROM (a FULL JOIN b USING(id)) LEFT JOIN (SELECT id FROM b) c USING(id) ORDER BY id',{'a':['id'],'b':['id']},True)
safe('derived/positional','SELECT d.secret FROM (SELECT id,k FROM a) d(secret,content) ORDER BY d.secret',{'a':['id','k']},True)
safe('derived/enclosing_scope','SELECT a.id FROM a WHERE EXISTS (SELECT 1 FROM (SELECT a.id AS k) d WHERE d.k>1) ORDER BY a.id',{'a':['id']},True)
safe('derived/lateral','SELECT a.id,d.k FROM a CROSS JOIN LATERAL (SELECT a.k+1 AS k) d ORDER BY a.id',{'a':['id','k']},True)
safe('derived/local_shadow','SELECT a.id FROM a WHERE EXISTS (SELECT 1 FROM (SELECT k AS secret FROM b) d WHERE secret>0)',{'a':['id'],'b':['k']})
safe('cte/positional_chain','WITH x(secret) AS (SELECT id FROM a), y(content) AS (SELECT secret FROM x) SELECT content FROM y ORDER BY content',{'a':['id']},True)
safe('cte/base_shadow','WITH a AS (SELECT k AS secret FROM b) SELECT secret FROM a ORDER BY secret',{'b':['k']},True)
safe('cte/nested_shadow','WITH x AS (SELECT id FROM a) SELECT d.id FROM (WITH x AS (SELECT id FROM b) SELECT id FROM x) d ORDER BY d.id',{'a':['id'],'b':['id']},True)
safe('cte/correlated','SELECT a.id FROM a WHERE EXISTS (WITH x AS (SELECT a.k AS secret) SELECT secret FROM x WHERE secret>0)',{'a':['id','k']})
safe('group/output_alias','SELECT k AS label,count(*) FROM a GROUP BY label ORDER BY label',{'a':['k']},True)
safe('group/ordinal','SELECT k,count(*) FROM a GROUP BY 1 ORDER BY 1',{'a':['k']},True)
safe('group/identical_labels','SELECT id AS label,a.id AS label,count(*) FROM a GROUP BY label ORDER BY label',{'a':['id']},True)
for form in ['GROUPING SETS ((label),())','ROLLUP(label)','CUBE(label)','(label)']:
    safe('group/'+form,'SELECT k AS label,count(*) FROM a GROUP BY '+form+' ORDER BY label NULLS LAST',{'a':['k']},True)
safe('group/input_before_output','SELECT min(id) AS k,count(*) FROM a GROUP BY k ORDER BY k',{'a':['id','k']},True)
safe('group/output_before_outer','SELECT a.id FROM a WHERE EXISTS (SELECT d.k AS secret,count(*) FROM (SELECT k FROM b) d GROUP BY secret)',{'a':['id'],'b':['k']})
safe('group/grouping_sets_before_outer','SELECT a.id FROM a WHERE EXISTS (SELECT d.k AS secret,count(*) FROM (SELECT k FROM b) d GROUP BY GROUPING SETS ((secret)))',{'a':['id'],'b':['k']})
safe('order/output_before_input','SELECT id AS secret FROM a ORDER BY secret DESC',{'a':['id']},True)
safe('order/identical_labels','SELECT id,a.id FROM a ORDER BY id DESC',{'a':['id']},True)
safe('order/expression_input','SELECT -id AS k FROM a ORDER BY k+1,id',{'a':['id','k']},True)
safe('order/ordinal','SELECT k,id FROM a ORDER BY 1 DESC,2',{'a':['id','k']},True)
safe('order/distinct_on_alias','SELECT DISTINCT ON (secret) id AS secret,k FROM a ORDER BY secret,k',{'a':['id','k']},True)
safe('order/aggregate_sort','SELECT array_agg(id ORDER BY k,id) AS ids FROM a',{'a':['id','k']})
for op in ['UNION','UNION ALL','INTERSECT','EXCEPT']:
    safe('set/'+op,'SELECT id AS secret FROM a '+op+' SELECT id FROM b ORDER BY secret DESC',{'a':['id'],'b':['id']},True)
safe('set/derived_positional','SELECT d.secret FROM (SELECT id FROM a UNION ALL SELECT k FROM b) d(secret) ORDER BY d.secret',{'a':['id'],'b':['k']},True)
safe('window/partition_order','SELECT id,row_number() OVER(PARTITION BY k ORDER BY id) AS n FROM a ORDER BY id',{'a':['id','k']},True)
safe('window/named_inheritance','SELECT id,sum(k) OVER w2 AS total FROM a WINDOW w AS (PARTITION BY k),w2 AS (w ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) ORDER BY id',{'a':['id','k']},True)
safe('window/filter','SELECT id,count(*) FILTER(WHERE k>10) OVER(ORDER BY id) AS n FROM a ORDER BY id',{'a':['id','k']},True)
safe('window/input_alias_collision','SELECT id AS secret,row_number() OVER(ORDER BY id) AS n FROM a ORDER BY secret',{'a':['id']},True)
safe('coercion/using_text','SELECT txt FROM a FULL JOIN b USING(txt) ORDER BY txt',{'a':['txt'],'b':['txt']},True)
safe('coercion/union_unknown','SELECT txt FROM a UNION SELECT NULL ORDER BY txt NULLS LAST',{'a':['txt']},True)
safe('coercion/case','SELECT CASE WHEN k>10 THEN id ELSE 2147483648 END AS n FROM a ORDER BY id',{'a':['id','k']},True)
safe('coercion/array','SELECT ARRAY[id]::bigint[] AS ids FROM a ORDER BY id',{'a':['id']},True)
safe('coercion/function','SELECT lower(txt),coalesce(k,0) FROM a ORDER BY id',{'a':['id','k','txt']},True)
for expr,col in [('id+1','id'),('lower(txt)','txt'),('id::bigint','id'),('coalesce(k,0)','k')]:
    safe('order/duplicate_expression_'+expr,'SELECT '+expr+' AS label,'+expr+' AS label FROM a ORDER BY label',{'a':[col]},True)
    safe('group/duplicate_expression_'+expr,'SELECT '+expr+' AS label,'+expr+' AS label,count(*) FROM a GROUP BY label',{'a':[col]})
safe('window/frame_subquery','SELECT id,sum(k) OVER(ORDER BY id ROWS BETWEEN (SELECT min(id) FROM b) PRECEDING AND CURRENT ROW) FROM a ORDER BY id',{'a':['id','k'],'b':['id']},True)
safe('group/using_coercion','SELECT id+2147483647 AS n,count(*) FROM a LEFT JOIN b USING(id) GROUP BY id ORDER BY id',{'a':['id'],'b':['id']},True)
safe('derived/using_coercion','SELECT d.id+2147483647 AS n FROM (SELECT id FROM a JOIN b USING(id)) d ORDER BY d.id',{'a':['id'],'b':['id']},True)
safe('cte/using_coercion','WITH x AS (SELECT id FROM a JOIN b USING(id)) SELECT id+2147483647 AS n FROM x ORDER BY id',{'a':['id'],'b':['id']},True)
for tier in ['content','secret','restricted']:
    patterns={
      'projection':f'SELECT {tier} FROM a',
      'where':f'SELECT id FROM a WHERE {tier}>0',
      'join_on':f'SELECT a.id FROM a JOIN b ON a.{tier}=b.id',
      'join_using':f'SELECT a.id FROM a JOIN b USING({tier})',
      'join_alias':f'SELECT j.{tier} FROM (a FULL JOIN b USING(id)) j',
      'derived':f'SELECT d.id FROM (SELECT {tier} AS id FROM a) d',
      'lateral':f'SELECT d.id FROM a CROSS JOIN LATERAL (SELECT a.{tier} AS id) d',
      'outer_derived':f'SELECT a.id FROM a WHERE EXISTS (SELECT 1 FROM (SELECT a.{tier} AS k) d WHERE k>0)',
      'inner_shadows_outer':f'SELECT a.id FROM (SELECT id AS {tier},id FROM a) a WHERE EXISTS (SELECT 1 FROM b WHERE {tier}>0)',
      'cte':f'WITH x(id) AS (SELECT {tier} FROM a) SELECT id FROM x',
      'group_input_collision':f'SELECT min(id) AS {tier},count(*) FROM a GROUP BY {tier}',
      'group_sets':f'SELECT count(*) FROM a GROUP BY GROUPING SETS (({tier}),())',
      'group_rollup':f'SELECT count(*) FROM a GROUP BY ROLLUP(id,{tier})',
      'group_cube':f'SELECT count(*) FROM a GROUP BY CUBE({tier})',
      'having':f'SELECT k,count(*) FROM a GROUP BY k HAVING sum({tier})>0',
      'order_qualified':f'SELECT id AS {tier} FROM a ORDER BY a.{tier}',
      'order_expression':f'SELECT id AS {tier} FROM a ORDER BY {tier}+1',
      'distinct_expression':f'SELECT DISTINCT ON ({tier}+1) id AS {tier} FROM a ORDER BY {tier}+1',
      'aggregate_sort':f'SELECT array_agg(id ORDER BY {tier}) FROM a',
      'set_rhs':f'SELECT id FROM a UNION SELECT {tier} FROM b',
      'window_partition':f'SELECT id AS {tier},row_number() OVER(PARTITION BY {tier}) FROM a',
      'window_order':f'SELECT id AS {tier},row_number() OVER(ORDER BY {tier}) FROM a',
      'window_frame_subquery':f'SELECT id,sum(k) OVER(ORDER BY id ROWS BETWEEN (SELECT min({tier}) FROM b) PRECEDING AND CURRENT ROW) FROM a',
      'window_named':f'SELECT id,sum(k) OVER w FROM a WINDOW w AS (ORDER BY {tier})',
      'aggregate_filter':f'SELECT count(*) FILTER(WHERE {tier}>0) FROM a',
      'coercion':f'SELECT coalesce({tier}::bigint,0) FROM a',
    }
    # Duplicate labels on the join are removed using explicit positional aliases.
    patterns['join_alias']=f'SELECT j.hidden FROM (a JOIN b USING(id)) j(key,ak,hidden)'
    if tier!='content':
        patterns['join_alias']=f'SELECT j.hidden FROM (a JOIN b USING(id)) j('+','.join(['key','ak','ac','asecret','ar'][:['content','secret','restricted'].index(tier)+2])+',hidden)'
    for shape,sql in patterns.items(): deny('deny/'+tier+'/'+shape,sql,tier)
Path(__file__).with_name('postgres_resolution_review.json').write_text(json.dumps(cases,indent=2)+'\n')
print(len(cases),'cases')
