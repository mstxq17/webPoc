# Forward
在先知看了梅子酒师傅发的cve,然后觉得有趣就分析了一番,发现利用过程可以更加简便，无限制报错注入，通杀finecms最新版之类的把 我谷歌基本关键字finecms5.3.0公益版基本通杀  而且这个点我也感觉很容易出现在cms中 一般我们认为调用模块是不经过数据库的所以就很大意了.下面看代码分析过程(ps：之前答应key表哥文章首发胖虎的结果自己偷懒了，所以特意熬夜准备这篇首发到了胖虎)

# Analyze
首先确定程序框架:ci框架  那么ci框架的话我们可以去看文档 了解传参过程
举个例子: (int)$this->input->get('id');通过input对象的get属性方法得到$_GET数组处理 得到参数id的值然后强制整形
代码位置://finecms/dayrui/controllers/member/Api.php 590行
```
    public function checktitle() {

        $id = (int)$this->input->get('id');//上面分析过了这里是不存在注入了
        $title = $this->input->get('title', TRUE);//这里第二个参数用了TRUE 也就是开启了xss_clean 其中的过滤比较严格 无法逃逸单引号 过滤了很多危险函数 所以这里无法注入 这个是程序本身的过滤 这里不考虑绕过的可行性
        $module = $this->input->get('module');//注入点在这 得到module的值赋给$module变量
        (!$title || !$module) && exit('');//判断是否存在 截断性质 前面结果为假 exit就不执行也就是 titile和module不为空
        $num = $this->db->where('id<>', $id)->where('title', $title)->count_all_results(SITE_ID.'_'.$module);//这里实例化db对象访问where方法返回新的对象继续访问where方法然后返回新的对象去访问count_all_results属性方法
这里带入了我们可控的值 我们跟进这个函数看看有没有第二重过滤
        $num ? exit(fc_lang('<font color=red>'.fc_lang('重复').'</font>')) : exit('');
    }
```

count_all_results函数 文件:
这个在ci框架的db_query里面 其实都不用分析就行了自己去看下文档就行 根本没有任何处理就带入了from子句
不过考虑到一些新手带着你们去读下代码
![file](http://ozpdcy1zs.bkt.clouddn.com/d798063fd458ddabdc52365eb82f8d14.png-quanzi)
1396行：
```
	public function count_all_results($table = '', $reset = TRUE)
	{
		if ($table !== '')//传入的值不为空进入语句
		{
			$this->_track_aliases($table);//进入这个函数进行处理
			$this->from($table);//进入函数处理 我们跟进这个两个函数讲解下是否有过滤
		}
		// ORDER BY usage is often problematic here (most notably
		// on Microsoft SQL Server) and ultimately unnecessary
		// for selecting COUNT(*) ...
		if ( ! empty($this->qb_orderby))
		{
			$orderby = $this->qb_orderby;
			$this->qb_orderby = NULL;
		}
		echo $this->_compile_select();
		$result = ($this->qb_distinct === TRUE OR ! empty($this->qb_groupby) OR ! empty($this->qb_cache_groupby) OR $this->qb_limit OR $this->qb_offset)
			? $this->query($this->_count_string.$this->protect_identifiers('numrows')."\nFROM (\n".$this->_compile_select()."\n) CI_count_all_results")
			: $this->query($this->_compile_select($this->_count_string.$this->protect_identifiers('numrows')));

		if ($reset === TRUE)
		{
			$this->_reset_select();
		}
		// If we've previously reset the qb_orderby values, get them back
		elseif ( ! isset($this->qb_orderby))
		{
			$this->qb_orderby = $orderby;
		}

		if ($result->num_rows() === 0)
		{
			return 0;
		}

		$row = $result->row();
		return (int) $row->numrows;
	}
```

同文件下 2263行开始     function _track_aliases
```
	protected function _track_aliases($table)
	{
		if (is_array($table))//如果是数组
		{
			foreach ($table as $t)//遍历数组的每个值
			{
				$this->_track_aliases($t);//把每个值重新代入该函数处理
			}
			return;
		}
//举个例子array('123','456')遍历的 123因为不是数组代入下面处理一次 同理 456也带入下面处理一次
		// Does the string contain a comma?  If so, we need to separate
		// the string into discreet statements
		if (strpos($table, ',') !== FALSE)/如果存在,那么就把，分割成数组在带进去函数
		{
			return $this->_track_aliases(explode(',', $table));
		}

		// if a table alias is used we can recognize it by a space
		if (strpos($table, ' ') !== FALSE)//不存在空格就跳过该函数了 下面代码跟漏洞无关就不分析了
		{
.......省略
	}
```
这个从上面代码分析函数可以说毫无卵用  因为没赋值给什么东西也没执行什么纯粹就是遍历 所以这个东西对我们的注入语句没有影响  

因为前面的语句没有对$table变量进行修改 所以$table还是原来的进入from函数  
下面我们看from函数 同文件下472行:
```
	public function from($from)
	{
		foreach ((array) $from as $val)//$from强制转换为数组然后进行遍历比如传入new123,123->array('new123,123')
		{
			if (strpos($val, ',') !== FALSE)//存在逗号进入下面语句
			{
				foreach (explode(',', $val) as $v)//分割，成为数组进行遍历
				{
					$v = trim($v);//去除两边空格
					$this->_track_aliases($v);//前面说了毫无卵用

					$this->qb_from[] = $v = $this->protect_identifiers($v, TRUE, NULL, FALSE);
					if ($this->qb_caching === TRUE)//初始化时候为真进入下面语句
					{
						$this->qb_cache_from[] = $v;//为属性数组赋值 就是遍历出来的$v其中包括了我们的语句 这个会在comileselect方法会用上进行查询
						$this->qb_cache_exists[] = 'from';//同上
					}
				}
			}
			else//只要我们传入逗号下面就不进去了 代码和上面没太大差别
			{
				$val = trim($val);

				// Extract any aliases that might exist. We use this information
				// in the protect_identifiers to know whether to add a table prefix
				$this->_track_aliases($val);

				$this->qb_from[] = $val = $this->protect_identifiers($val, TRUE, NULL, FALSE);

				if ($this->qb_caching === TRUE)
				{
					$this->qb_cache_from[] = $val;
					$this->qb_cache_exists[] = 'from';
				}
			}
		}

		return $this;
	}
```

通过上面可以知道 第一个函数毫无卵用 第二个函数没经过什么鬼过滤函数 不过对一些类的属性值进行了添加
其中包括了我们的可控的点 那么只要可控的点进入查询即可    
回到count_all_results函数继续读下去  
```
if ( ! empty($this->qb_orderby))//判断这个order by不为空进入
		{
			$orderby = $this->qb_orderby;//赋值
			$this->qb_orderby = NULL;//重新置空
		}
		$result = ($this->qb_distinct === TRUE OR ! empty($this->qb_groupby) OR ! empty($this->qb_cache_groupby) OR $this->qb_limit OR $this->qb_offset)//or只要满足即可一个即可 下面就是query啦字符串拼接然后查询 ，query的实现就不带了涉及到框架的处理  这里我们探讨注入的可控传递到数据库 
			? $this->query($this->_count_string.$this->protect_identifiers('numrows')."\nFROM (\n".$this->_compile_select()."\n) CI_count_all_results")//我们构造的payload是进去else语句的
			: $this->query($this->_compile_select($this->_count_string.$this->protect_identifiers('numrows')));//这里有个$this->_compile_select 我们跟进一下
finecms\finecms\system\database\DB_forge.php 2316行
```
protected function _compile_select($select_override = FALSE)
	{
		// Combine any cached components with the current statements
		$this->_merge_cache();//跟进一下  就会发现  把之前我们的from函数存储的值在$this->qb_cache_from[]复制给了qb_no_escape 然后我们继续读下去
	
		// Write the "select" portion of the query
		if ($select_override !== FALSE)
		{
			$sql = $select_override;
		}
		else
		{
			$sql = ( ! $this->qb_distinct) ? 'SELECT ' : 'SELECT DISTINCT ';
	
			if (count($this->qb_select) === 0)
			{
				$sql .= '*';
			}
			else
			{
				// Cycle through the "select" portion of the query and prep each column name.
				// The reason we protect identifiers here rather than in the select() function
				// is because until the user calls the from() function we don't know if there are aliases
				foreach ($this->qb_select as $key => $val)
				{
					$no_escape = isset($this->qb_no_escape[$key]) ? $this->qb_no_escape[$key] : NULL;//这里便带入了我们的语句
					$this->qb_select[$key] = $this->protect_identifiers($val, FALSE, $no_escape);//处理上面变量带入
				}
	
				$sql .= implode(', ', $this->qb_select);//拼接sql语句
			}
		}
	
		// Write the "FROM" portion of the query
		if (count($this->qb_from) > 0)
		{
			$sql .= "\nFROM ".$this->_from_tables();
		}
	
		// Write the "JOIN" portion of the query
		if (count($this->qb_join) > 0)
		{
			$sql .= "\n".implode("\n", $this->qb_join);
		}
	
		$sql .= $this->_compile_wh('qb_where')
			.$this->_compile_group_by()
			.$this->_compile_wh('qb_having')
			.$this->_compile_order_by(); // ORDER BY
	
		// LIMIT
		if ($this->qb_limit OR $this->qb_offset)
		{
			return $this->_limit($sql."\n");
		}
	
		return $sql;//返回
	}

```
这里我分析比较简单 因为只要带你们走到这里明白这里入库就行了   比较晚了  哎4:00

# Payload
    

![file](http://ozpdcy1zs.bkt.clouddn.com/1ed2e17b139af2e711c0408c077b6c85.png-quanzi)

这个默认安装支持报错  所以直接带入报错语句即可  因为在from后面 需要增加表名  这里我用了c  
关于这个构造原理之前我发了一篇文章在tools  就是mysql支持嵌套表  
select * from (select *  from admin)之类的 所以我们可以通过 select 报错语句构造合法sql语句 然后进行报错    
ps(报错的前提是sql语句合法  新手很喜欢混淆概念  报错是进了查询的 语法错误是没进行查询的)  
```