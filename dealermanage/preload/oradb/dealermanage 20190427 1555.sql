-- MySQL Administrator dump 1.4
--
-- ------------------------------------------------------
-- Server version	5.0.91-community-nt


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;


--
-- Create schema dealermanage
--

CREATE DATABASE IF NOT EXISTS dealermanage;
USE dealermanage;

--
-- Definition of table `account`
--

DROP TABLE IF EXISTS `account`;
CREATE TABLE `account` (
  `account_id` varchar(25) NOT NULL,
  `account_type` varchar(25) NOT NULL,
  `account_name` varchar(40) default NULL,
  `description` varchar(200) default NULL,
  `previous_balance` double default NULL,
  `current_balance` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `account`
--

/*!40000 ALTER TABLE `account` DISABLE KEYS */;
INSERT INTO `account` (`account_id`,`account_type`,`account_name`,`description`,`previous_balance`,`current_balance`,`created`,`updated`) VALUES 
 ('ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',5164.82,5282.1,'20190408225318','20190427150859'),
 ('ACCT1000000002','SALESMAN','K.M. Rashedul Islam','K.M. Rashedul Islam',0,0,'20190409235715','20190416095003'),
 ('ACCT1000000003','SALESMAN','Nayem Shihab Uddin Noor','Nayem Shihab Uddin Noor',0,0,'20190409235852','20190416114257'),
 ('ACCT1000000004','OTHER','Other','Other',0,0,'20190419115556','20190419115629');
/*!40000 ALTER TABLE `account` ENABLE KEYS */;


--
-- Definition of table `area`
--

DROP TABLE IF EXISTS `area`;
CREATE TABLE `area` (
  `area_id` varchar(25) NOT NULL,
  `area_name` varchar(40) NOT NULL,
  `state_city_id` varchar(25) default NULL,
  `state_name` varchar(40) default NULL,
  `city_name` varchar(40) default NULL,
  `country_id` varchar(25) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`area_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `area`
--

/*!40000 ALTER TABLE `area` DISABLE KEYS */;
/*!40000 ALTER TABLE `area` ENABLE KEYS */;


--
-- Definition of table `bonus_details`
--

DROP TABLE IF EXISTS `bonus_details`;
CREATE TABLE `bonus_details` (
  `bonus_id` varchar(25) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `bonus_for` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `bonus_point` varchar(40) default NULL,
  `bonus_item` varchar(200) default NULL,
  `bonus_gift` varchar(200) default NULL,
  `description` varchar(200) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`bonus_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `bonus_details`
--

/*!40000 ALTER TABLE `bonus_details` DISABLE KEYS */;
/*!40000 ALTER TABLE `bonus_details` ENABLE KEYS */;


--
-- Definition of table `brand`
--

DROP TABLE IF EXISTS `brand`;
CREATE TABLE `brand` (
  `brand_id` varchar(25) NOT NULL,
  `brand_name` varchar(100) NOT NULL,
  `product_category_id` varchar(25) NOT NULL,
  `generic_id` varchar(25) NOT NULL,
  `generic_name` varchar(100) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `company_id` varchar(25) NOT NULL,
  `company_name` varchar(100) NOT NULL,
  PRIMARY KEY  (`brand_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `brand`
--

/*!40000 ALTER TABLE `brand` DISABLE KEYS */;
INSERT INTO `brand` (`brand_id`,`brand_name`,`product_category_id`,`generic_id`,`generic_name`,`created`,`updated`,`company_id`,`company_name`) VALUES 
 ('BRND1000000001','Matador High School','PRODCAT1000001','GENRIC10000001','Ball Pens','20190408230646','20190408230843','COMP1000000001','Matador'),
 ('BRND1000000002','Matador Radiant','PRODCAT1000001','GENRIC10000001','Ball Pens','20190409112924','20190409113000','COMP1000000001','Matador'),
 ('BRND1000000003','Matador Orbit','PRODCAT1000001','GENRIC10000001','Ball Pens','20190409113227','','COMP1000000001','Matador'),
 ('BRND1000000004','Matador Rio','PRODCAT1000001','GENRIC10000001','Ball Pens','20190417010816','20190417010858','COMP1000000001','Matador'),
 ('BRND1000000005','Matador i-teen','PRODCAT1000001','GENRIC10000001','Ball Pens','20190419182551','','COMP1000000001','Matador'),
 ('BRND1000000006','Matador Wood','PRODCAT1000001','GENRIC10000001','Ball Pens','20190426210907','20190426211012','COMP1000000001','Matador'),
 ('BRND1000000007','Matador Rio','PRODCAT1000001','GENRIC10000001','Ball Pens','20190427152854','','COMP1000000001','Matador');
/*!40000 ALTER TABLE `brand` ENABLE KEYS */;


--
-- Definition of table `company`
--

DROP TABLE IF EXISTS `company`;
CREATE TABLE `company` (
  `company_id` varchar(25) NOT NULL,
  `company_name` varchar(100) NOT NULL,
  `description` varchar(200) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`company_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `company`
--

/*!40000 ALTER TABLE `company` DISABLE KEYS */;
INSERT INTO `company` (`company_id`,`company_name`,`description`,`created`,`updated`) VALUES 
 ('COMP1000000001','Matador','Mother Brand','20190408230618','');
/*!40000 ALTER TABLE `company` ENABLE KEYS */;


--
-- Definition of table `country`
--

DROP TABLE IF EXISTS `country`;
CREATE TABLE `country` (
  `country_id` varchar(25) NOT NULL,
  `country_name` varchar(40) NOT NULL,
  `two_digit_county_code_alph` varchar(2) default NULL,
  `three_digit_county_code_alph` varchar(3) default NULL,
  `two_digit_county_code_num` int(2) default NULL,
  `three_digit_county_code_num` int(3) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`country_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `country`
--

/*!40000 ALTER TABLE `country` DISABLE KEYS */;
/*!40000 ALTER TABLE `country` ENABLE KEYS */;


--
-- Definition of table `customer_info`
--

DROP TABLE IF EXISTS `customer_info`;
CREATE TABLE `customer_info` (
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `customer_desc` varchar(40) default NULL,
  `customer_type` varchar(25) default NULL,
  `customer_start_date` varchar(14) default NULL,
  `father_name` varchar(40) NOT NULL,
  `mother_name` varchar(40) default NULL,
  `nid` varchar(40) default NULL,
  `dob` varchar(25) default NULL,
  `occupation` varchar(40) default NULL,
  `country_id` varchar(25) default NULL,
  `mobile` varchar(40) NOT NULL,
  `email` varchar(200) default NULL,
  `account_id` varchar(25) default NULL,
  `home_address` varchar(200) NOT NULL,
  `office_address` varchar(200) default NULL,
  `profession` varchar(40) default NULL,
  `password` varchar(100) NOT NULL,
  `status` varchar(1) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`customer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_info`
--

/*!40000 ALTER TABLE `customer_info` DISABLE KEYS */;
INSERT INTO `customer_info` (`customer_id`,`customer_name`,`customer_desc`,`customer_type`,`customer_start_date`,`father_name`,`mother_name`,`nid`,`dob`,`occupation`,`country_id`,`mobile`,`email`,`account_id`,`home_address`,`office_address`,`profession`,`password`,`status`,`created`,`updated`) VALUES 
 ('CUST1000000001','K.M. Rashedul Islam','K.M. Rashedul Islam','K.M. Rashedul Islam','20190301122619','Ali Ahammed','Rashida Sultana','20190217155348','19880101','Software Engineer','BD','01818327407','islamrashedul91@gmail.com','','Wapda Staff Quarter, Mirpur-12, Dhaka','','Software Engineer','81dc9bdb52d04dc20036dbd8313ed055','A','20190301122619',''),
 ('CUST1000000002','Sumon','Sumon','Sumon','20190301122808','Ali Ahammed','Rashida Sultana','20190217155348','19880101','Software Engineer','BD','01683804300','rashedul@icliquebd.com','ncc','Mirpur - 12','','Software Engineer','b06de212b821659277d610b28ad7357c','A','20190301122808','20190311160129'),
 ('CUST1000000003','Nayem Shihab Uddin Noor','Nayem Shihab Uddin Noor','Nayem Shihab Uddin Noor','20190311160204','Noor','Mrs Noor','20190217155348','19880101','Software Engineer','BD','01613600471','nayem@gmail.com','ncc','Kazipara','Mohakhali','Executive Officer','81dc9bdb52d04dc20036dbd8313ed055','B','20190311160204','20190311162140'),
 ('CUST1000000004','Test User','Test User','Test User','20190311163455','Test User','Test User','20190217155348','19880101','Test User','BD','01818888888','testuser@gmail.com','ncc','Test User','Test User','Test User','b06de212b821659277d610b28ad7357c','C','20190311163455','20190311163859'),
 ('CUST1000000005','Mohiuddin Mithu','','Regular','20190404163317','Mohammad Ali','Mrs Mohammad Ali','20190217155348','19880101','','BD','01815228050','mithu@gmail.com','ncc','Savar','New Market','Business Man','81dc9bdb52d04dc20036dbd8313ed055','A','20190404163317',''),
 ('CUST1000000006','Tasnim Jahan Rojoni Athoy','','Regular','20190404221413','Ripon Howladar','Tahmina Aktar Monzue','20190217155348','19880101','','BD','01673376181','ali@gmail.com','10008','Mirpur - 12','Tongi','Employee','81dc9bdb52d04dc20036dbd8313ed055','A','20190404221413','');
/*!40000 ALTER TABLE `customer_info` ENABLE KEYS */;


--
-- Definition of table `customer_purchase`
--

DROP TABLE IF EXISTS `customer_purchase`;
CREATE TABLE `customer_purchase` (
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`purchase_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_purchase`
--

/*!40000 ALTER TABLE `customer_purchase` DISABLE KEYS */;
/*!40000 ALTER TABLE `customer_purchase` ENABLE KEYS */;


--
-- Definition of table `customer_purchase_main`
--

DROP TABLE IF EXISTS `customer_purchase_main`;
CREATE TABLE `customer_purchase_main` (
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`purchase_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_purchase_main`
--

/*!40000 ALTER TABLE `customer_purchase_main` DISABLE KEYS */;
INSERT INTO `customer_purchase_main` (`purchase_id`,`purchase_type`,`requisition_id`,`date_time`,`customer_id`,`customer_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`salesman_id`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('CSTP1000000001','Requisition','REQU1000000001','20190409111059','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000002',1960,'S','D','20190409111059','20190409111132','',''),
 ('CSTP1000000002','Requisition','REQU1000000001','20190409113439','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',303.4,'S','D','20190409113439','20190409111132','',''),
 ('CSTP1000000003','Requisition','REQU1000000004','20190409155210','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000001',196,'S','D','20190409155210','20190409153950','',''),
 ('CSTP1000000004','Requisition','REQU1000000005','20190409233150','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',1466,'S','D','20190409233150','20190409233851','',''),
 ('CSTP1000000005','Requisition','REQU1000000007','20190414190540','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000001',782.4,'S','D','20190414190540','20190414190734','',''),
 ('CSTP1000000006','Requisition','REQU1000000008','20190415130912','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',709.1,'S','D','20190415130912','20190416021722','',''),
 ('CSTP1000000007','Requisition','REQU1000000009','20190416022748','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',2744,'S','D','20190416022748','20190416022829','',''),
 ('CSTP1000000008','Requisition','REQU1000000012','20190419193206','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',1125,'S','D','20190419193206','20190419193202','',''),
 ('CSTP1000000009','Requisition','REQU1000000012','20190419195037','CUST1000000004','Test User','01818888888','','ACCT1000000001','','SMAN1000000002',366.5,'S','D','20190419195037','20190420035450','',''),
 ('CSTP1000000010','Requisition','REQU1000000014','20190420045918','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',219.9,'S','D','20190420045918','20190420045915','',''),
 ('CSTP1000000011','Requisition','REQU1000000015','20190420050117','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000002',366.5,'S','D','20190420050117','20190420050114','',''),
 ('CSTP1000000012','Requisition','REQU1000000016','20190421000622','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',196,'S','D','20190421000622','20190421112333','',''),
 ('CSTP1000000013','Requisition','REQU1000000017','20190421121139','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',366.5,'S','D','20190421121139','20190421121131','',''),
 ('CSTP1000000014','Requisition','REQU1000000020','20190421144231','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000001',748,'S','D','20190421144231','20190421144812','',''),
 ('CSTP1000000015','Requisition','REQU1000000021','20190422060245','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',11.25,'S','D','20190422060245','20190422161918','',''),
 ('CSTP1000000016','Requisition','REQU1000000023','20190422162433','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',127.61,'S','D','20190422162433','20190422161918','',''),
 ('CSTP1000000017','Requisition','REQU1000000024','20190423163714','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',371.6,'S','D','20190423163714','20190423163648','',''),
 ('CSTP1000000018','Requisition','REQU1000000027','20190426122338','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000002',311.66,'S','D','20190426122338','20190426122335','',''),
 ('CSTP1000000019','Requisition','REQU1000000028','20190427024142','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',264.9,'S','D','20190427024142','20190427024139','',''),
 ('CSTP1000000020','Requisition','REQU1000000029','20190427151106','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000002',117.28,'S','D','20190427151106','20190427150859','','');
/*!40000 ALTER TABLE `customer_purchase_main` ENABLE KEYS */;


--
-- Definition of table `customer_purchase_product`
--

DROP TABLE IF EXISTS `customer_purchase_product`;
CREATE TABLE `customer_purchase_product` (
  `purchase_product_id` varchar(25) NOT NULL,
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `requisition_product_id` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`purchase_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_purchase_product`
--

/*!40000 ALTER TABLE `customer_purchase_product` DISABLE KEYS */;
INSERT INTO `customer_purchase_product` (`purchase_product_id`,`purchase_id`,`purchase_type`,`requisition_product_id`,`requisition_id`,`date_time`,`product_id`,`product_name`,`pack_type`,`pack_size`,`piceces`,`bonus_id`,`bonus_name`,`order_pack`,`order_quantity`,`mrp_price`,`total_mrp_price`,`discount_amt`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('PPDT1000000001','CSTP1000000001','Requisition','RPDT1000000001','REQU1000000001','20190409111059','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',500,3.92,1960,0,1960,'S','D','20190409111113','20190409111132','',''),
 ('PPDT1000000002','CSTP1000000002','Requisition','RPDT1000000001','REQU1000000001','20190409113439','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',20,3.92,78.4,0,78.4,'S','D','20190409113453','20190409111132','',''),
 ('PPDT1000000003','CSTP1000000002','Requisition','RPDT1000000002','REQU1000000001','20190409113439','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',20,7.33,146.6,0,146.6,'S','D','20190409113505','20190409111132','',''),
 ('PPDT1000000004','CSTP1000000002','Requisition','RPDT1000000003','REQU1000000001','20190409113439','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',20,3.92,78.4,0,78.4,'S','D','20190409113520','20190409111132','',''),
 ('PPDT1000000005','CSTP1000000003','Requisition','RPDT1000000001','REQU1000000004','20190409155210','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190409155446','20190409153950','',''),
 ('PPDT1000000006','CSTP1000000004','Requisition','RPDT1000000001','REQU1000000005','20190409233150','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',200,7.33,1466,0,1466,'S','D','20190410000040','20190409233851','',''),
 ('PPDT1000000007','CSTP1000000005','Requisition','RPDT1000000001','REQU1000000007','20190414190540','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190414190603','20190414190734','',''),
 ('PPDT1000000008','CSTP1000000005','Requisition','RPDT1000000002','REQU1000000007','20190414190540','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',80,7.33,586.4,0,586.4,'S','D','20190414190641','20190414190734','',''),
 ('PPDT1000000009','CSTP1000000006','Requisition','RPDT1000000001','REQU1000000008','20190415130912','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190415130924','20190416021722','',''),
 ('PPDT1000000010','CSTP1000000006','Requisition','RPDT1000000002','REQU1000000008','20190415130912','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190415152710','20190416021722','',''),
 ('PPDT1000000011','CSTP1000000006','Requisition','RPDT1000000003','REQU1000000008','20190415130912','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',20,7.33,146.6,0,146.6,'S','D','20190415152750','20190416021722','',''),
 ('PPDT1000000012','CSTP1000000007','Requisition','RPDT1000000001','REQU1000000009','20190416022748','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',200,3.92,784,0,784,'S','D','20190416022758','20190416022829','',''),
 ('PPDT1000000013','CSTP1000000007','Requisition','RPDT1000000002','REQU1000000009','20190416022748','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',500,3.92,1960,0,1960,'S','D','20190416022813','20190416022829','',''),
 ('PPDT1000000014','CSTP1000000008','Requisition','RPDT1000000002','REQU1000000012','20190419193206','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',100,7.33,733,0,733,'S','D','20190419193249','20190419193202','',''),
 ('PPDT1000000015','CSTP1000000008','Requisition','RPDT1000000002','REQU1000000012','20190419193206','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190419193407','20190419193202','',''),
 ('PPDT1000000016','CSTP1000000008','Requisition','RPDT1000000002','REQU1000000012','20190419193206','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,NULL,'','',50,3.92,196,0,196,'S','D','20190419193437','20190419193202','',''),
 ('PPDT1000000017','CSTP1000000009','Requisition','RPDT1000000002','REQU1000000012','20190419195037','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190419195046','20190420035450','',''),
 ('PPDT1000000018','CSTP1000000010','Requisition','RPDT1000000002','REQU1000000014','20190420045918','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',30,7.33,219.9,0,219.9,'S','D','20190420045930','20190420045915','',''),
 ('PPDT1000000019','CSTP1000000011','Requisition','RPDT1000000002','REQU1000000015','20190420050117','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190420050125','20190420050114','',''),
 ('PPDT1000000020','CSTP1000000012','Requisition','RPDT1000000002','REQU1000000016','20190421000622','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190421000632','20190421112333','',''),
 ('PPDT1000000021','CSTP1000000013','Requisition','RPDT1000000002','REQU1000000017','20190421121139','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190421121157','20190421121131','',''),
 ('PPDT1000000022','CSTP1000000014','Requisition','RPDT1000000002','REQU1000000020','20190421144231','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190421144301','20190421144812','',''),
 ('PPDT1000000023','CSTP1000000014','Requisition','RPDT1000000002','REQU1000000020','20190421144231','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','','',50,7.63,381.5,0,381.5,'S','D','20190421144844','20190421144812','',''),
 ('PPDT1000000024','CSTP1000000015','Requisition','RPDT1000000002','REQU1000000021','20190422060245','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'','',1,7.33,7.33,0,7.33,'S','D','20190422060257','20190422161918','',''),
 ('PPDT1000000025','CSTP1000000015','Requisition','RPDT1000000002','REQU1000000021','20190422060245','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,NULL,'','',1,3.92,3.92,0,3.92,'S','D','20190422061450','20190422161918','',''),
 ('PPDT1000000026','CSTP1000000016','Requisition','RPDT1000000002','REQU1000000023','20190422162433','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'','',7,7.33,51.31,0,51.31,'S','D','20190422162448','20190422161918','',''),
 ('PPDT1000000027','CSTP1000000016','Requisition','RPDT1000000002','REQU1000000023','20190422162433','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,NULL,'','',10,7.63,76.3,0,76.3,'S','D','20190422162738','20190422161918','',''),
 ('PPDT1000000028','CSTP1000000017','Requisition','RPDT1000000002','REQU1000000024','20190423163714','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'','',40,7.33,293.2,0,293.2,'S','D','20190423163746','20190423163648','',''),
 ('PPDT1000000029','CSTP1000000017','Requisition','RPDT1000000002','REQU1000000024','20190423163714','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',20,3.92,78.4,0,78.4,'S','D','20190423163839','20190423163648','',''),
 ('PPDT1000000030','CSTP1000000018','Requisition','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','','',15,7.63,114.45,0,114.45,'S','D','20190426122345','20190426122335','',''),
 ('PPDT1000000031','CSTP1000000018','Requisition','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',13,7.33,95.29,0,95.29,'S','D','20190426122401','20190426122335','',''),
 ('PPDT1000000032','CSTP1000000018','Requisition','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',12,3.92,47.04,0,47.04,'S','D','20190426122411','20190426122335','',''),
 ('PPDT1000000033','CSTP1000000018','Requisition','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',14,3.92,54.88,0,54.88,'S','D','20190426122422','20190426122335','',''),
 ('PPDT1000000034','CSTP1000000019','Requisition','RPDT1000000002','REQU1000000028','20190427024142','PROD1000000006','Matador Wood .5 ball pen','strip','1',12,'','','',30,8.83,264.9,0,264.9,'S','D','20190427024155','20190427024139','',''),
 ('PPDT1000000035','CSTP1000000020','Requisition','RPDT1000000002','REQU1000000029','20190427151106','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',10,7.33,73.3,0,73.3,'S','D','20190427151402','20190427150859','',''),
 ('PPDT1000000036','CSTP1000000020','Requisition','RPDT1000000002','REQU1000000029','20190427151106','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,NULL,'','',6,7.33,43.98,0,43.98,'S','D','20190427151536','20190427150859','','');
/*!40000 ALTER TABLE `customer_purchase_product` ENABLE KEYS */;


--
-- Definition of table `customer_transaction`
--

DROP TABLE IF EXISTS `customer_transaction`;
CREATE TABLE `customer_transaction` (
  `transaction_id` varchar(25) NOT NULL,
  `transaction_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) default NULL,
  `customer_id` varchar(25) default NULL,
  `customer_name` varchar(40) default NULL,
  `mobile` varchar(40) default NULL,
  `product_id` varchar(25) default NULL,
  `product_name` varchar(100) default NULL,
  `pack_type` varchar(40) default NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_transaction`
--

/*!40000 ALTER TABLE `customer_transaction` DISABLE KEYS */;
/*!40000 ALTER TABLE `customer_transaction` ENABLE KEYS */;


--
-- Definition of table `customer_transaction_main`
--

DROP TABLE IF EXISTS `customer_transaction_main`;
CREATE TABLE `customer_transaction_main` (
  `transaction_id` varchar(25) NOT NULL,
  `transaction_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  `reason` varchar(200) default NULL,
  PRIMARY KEY  (`transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_transaction_main`
--

/*!40000 ALTER TABLE `customer_transaction_main` DISABLE KEYS */;
INSERT INTO `customer_transaction_main` (`transaction_id`,`transaction_type`,`requisition_id`,`date_time`,`customer_id`,`customer_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`salesman_id`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`,`reason`) VALUES 
 ('TRNX1000000001','Purchase','REQU1000000025','20190426115631','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',104.66,'S','R','20190426115631','20190426115643','','',''),
 ('TRNX1000000002','Purchase','REQU1000000025','20190426115631','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',89.46,'S','R','20190426115631','20190426114900','','',''),
 ('TRNX1000000003','Purchase','REQU1000000026','20190426121311','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000001',317.12,'S','R','20190426121311','20190426121237','','',''),
 ('TRNX1000000004','Purchase','REQU1000000029','20190427151106','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000002',164.6,'S','R','20190427151106','20190427151259','','','');
/*!40000 ALTER TABLE `customer_transaction_main` ENABLE KEYS */;


--
-- Definition of table `customer_transaction_product`
--

DROP TABLE IF EXISTS `customer_transaction_product`;
CREATE TABLE `customer_transaction_product` (
  `transaction_product_id` varchar(25) NOT NULL,
  `transaction_id` varchar(25) NOT NULL,
  `transaction_type` varchar(25) NOT NULL,
  `requisition_product_id` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  `reason` varchar(200) default NULL,
  PRIMARY KEY  (`transaction_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `customer_transaction_product`
--

/*!40000 ALTER TABLE `customer_transaction_product` DISABLE KEYS */;
INSERT INTO `customer_transaction_product` (`transaction_product_id`,`transaction_id`,`transaction_type`,`requisition_product_id`,`requisition_id`,`date_time`,`product_id`,`product_name`,`pack_type`,`pack_size`,`piceces`,`bonus_id`,`bonus_name`,`order_pack`,`order_quantity`,`mrp_price`,`total_mrp_price`,`discount_amt`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`,`reason`) VALUES 
 ('TPDT1000000001','TRNX1000000001','Purchase','RPDT1000000002','REQU1000000025','20190426115631','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',10,7.33,73.3,0,73.3,'S','R','20190426115643','20190426115643','','',''),
 ('TPDT1000000002','TRNX1000000001','Purchase','RPDT1000000002','REQU1000000025','20190426115631','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',8,3.92,31.36,0,31.36,'S','R','20190426115747','20190426115643','','',''),
 ('TPDT1000000003','TRNX1000000001','Purchase','RPDT1000000002','REQU1000000025','20190426115631','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,NULL,'','',5,7.63,38.15,0,38.15,'S','R','20190426115659','20190426114900','','',''),
 ('TPDT1000000004','TRNX1000000001','Purchase','RPDT1000000002','REQU1000000025','20190426115631','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',7,7.33,51.31,0,51.31,'S','R','20190426115756','20190426114900','','',''),
 ('TPDT1000000005','TRNX1000000003','Purchase','RPDT1000000002','REQU1000000026','20190426121311','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',7,7.33,51.31,0,51.31,'S','R','20190426121333','20190426121333','','',''),
 ('TPDT1000000006','TRNX1000000003','Purchase','RPDT1000000002','REQU1000000026','20190426121311','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',9,3.92,35.28,0,35.28,'S','R','20190426121351','20190426121333','','',''),
 ('TPDT1000000007','TRNX1000000003','Purchase','RPDT1000000002','REQU1000000026','20190426121311','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',8,7.33,58.64,0,58.64,'S','R','20190426121343','20190426121237','','',''),
 ('TPDT1000000008','TRNX1000000003','Purchase','RPDT1000000002','REQU1000000026','20190426121311','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','','',11,7.63,83.93,0,83.93,'S','R','20190426121402','20190426121237','','',''),
 ('TPDT1000000009','TRNX1000000003','Purchase','RPDT1000000002','REQU1000000026','20190426121311','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',12,7.33,87.96,0,87.96,'S','R','20190426121412','20190426121237','','',''),
 ('TPDT1000000010','TRNX1000000004','Purchase','RPDT1000000002','REQU1000000029','20190427151106','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','','',10,7.63,76.3,0,76.3,'S','R','20190427151436','20190427151259','','',''),
 ('TPDT1000000011','TRNX1000000004','Purchase','RPDT1000000002','REQU1000000029','20190427151106','PROD1000000006','Matador Wood .5 ball pen','strip','1',12,'','','',10,8.83,88.3,0,88.3,'S','R','20190427151259','20190427151259','','','');
/*!40000 ALTER TABLE `customer_transaction_product` ENABLE KEYS */;


--
-- Definition of table `daily_sales`
--

DROP TABLE IF EXISTS `daily_sales`;
CREATE TABLE `daily_sales` (
  `sales_id` varchar(25) NOT NULL,
  `sales_type` varchar(25) NOT NULL,
  `salesman_id` varchar(25) default NULL,
  `salesman_name` varchar(40) default NULL,
  `date_time` varchar(14) default NULL,
  `product_id` varchar(25) default NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) default NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `from_account` varchar(25) default NULL,
  `to_account` varchar(25) default NULL,
  `account_id` varchar(25) default NULL,
  `total_amount` double default NULL,
  `last_day_amonut` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`sales_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `daily_sales`
--

/*!40000 ALTER TABLE `daily_sales` DISABLE KEYS */;
/*!40000 ALTER TABLE `daily_sales` ENABLE KEYS */;


--
-- Definition of table `day_wise_account_balance`
--

DROP TABLE IF EXISTS `day_wise_account_balance`;
CREATE TABLE `day_wise_account_balance` (
  `day_wise_balance_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `account_id` varchar(25) NOT NULL,
  `account_type` varchar(25) NOT NULL,
  `account_name` varchar(40) NOT NULL,
  `description` varchar(200) default NULL,
  `previous_balance` double default NULL,
  `credit_balance` double default NULL,
  `debit_balance` double default NULL,
  `current_balance` double default NULL,
  `day_balance` double NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`day_wise_balance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `day_wise_account_balance`
--

/*!40000 ALTER TABLE `day_wise_account_balance` DISABLE KEYS */;
INSERT INTO `day_wise_account_balance` (`day_wise_balance_id`,`date_time`,`account_id`,`account_type`,`account_name`,`description`,`previous_balance`,`credit_balance`,`debit_balance`,`current_balance`,`day_balance`,`created`,`updated`) VALUES 
 ('DWAB1000000001','20190409111016','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',0,1840,0,-1840,-1840,'20190409111016',''),
 ('DWAB1000000002','20190409111139','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',-1840,0,1960,120,120,'20190409111139',''),
 ('DWAB1000000003','20190409113552','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',120,0,303.4,423.4,423.4,'20190409113552',''),
 ('DWAB1000000004','20190409160026','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',423.4,0,196,619.4,619.4,'20190409160026',''),
 ('DWAB1000000005','20190410000116','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',619.4,0,1466,2085.4,2085.4,'20190410000116',''),
 ('DWAB1000000006','20190411192701','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',2085.4,528.5,0,1556.9,1556.9,'20190411192701',''),
 ('DWAB1000000007','20190414190830','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',1556.9,0,782.4,2339.3,2339.3,'20190414190830',''),
 ('DWAB1000000008','20190416015222','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',2339.3,660,0,1679.3,1679.3,'20190416015222',''),
 ('DWAB1000000009','20190416015707','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',1679.3,720,0,959.3,959.3,'20190416015707',''),
 ('DWAB1000000010','20190416020749','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',959.3,240,0,719.3,719.3,'20190416020749',''),
 ('DWAB1000000011','20190416021731','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',719.3,0,709.1,1428.4,1428.4,'20190416021731',''),
 ('DWAB1000000012','20190416022610','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',1428.4,720,0,708.4,708.4,'20190416022610',''),
 ('DWAB1000000013','20190416022836','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',708.4,0,2744,3452.4,3452.4,'20190416022836',''),
 ('DWAB1000000014','20190416105222','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3452.4,160,0,3292.4,3292.4,'20190416105222',''),
 ('DWAB1000000015','20190416111243','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3292.4,80,0,3212.4,3212.4,'20190416111243',''),
 ('DWAB1000000016','20190416112922','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3212.4,5,0,3207.4,3207.4,'20190416112922',''),
 ('DWAB1000000017','20190418112852','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3207.4,30,0,3177.4,3177.4,'20190418112852',''),
 ('DWAB1000000018','20190418213119','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3177.4,23,0,3154.4,3154.4,'20190418213119',''),
 ('DWAB1000000019','20190419193013','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3154.4,1451.6,0,1702.8,1702.8,'20190419193013',''),
 ('DWAB1000000020','20190419194323','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',1702.8,0,1125,2827.8,2827.8,'20190419194323',''),
 ('DWAB1000000021','20190420035627','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',2827.8,0,366.5,3194.3,3194.3,'20190420035627',''),
 ('DWAB1000000022','20190420050006','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3194.3,0,219.9,3414.2,3414.2,'20190420050006',''),
 ('DWAB1000000023','20190420050222','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3414.2,0,366.5,3780.7,3780.7,'20190420050222',''),
 ('DWAB1000000024','20190420233718','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3780.7,344.5,0,3436.2,3436.2,'20190420233718',''),
 ('DWAB1000000025','20190421112558','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3436.2,0,196,3632.2,3632.2,'20190421112558',''),
 ('DWAB1000000026','20190421121518','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3632.2,0,366.5,3998.7,3998.7,'20190421121518',''),
 ('DWAB1000000027','20190421145311','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',3998.7,0,748,4746.7,4746.7,'20190421145311',''),
 ('DWAB1000000028','20190422162317','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',4746.7,0,11.25,4757.95,4757.95,'20190422162317',''),
 ('DWAB1000000029','20190422163515','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',4757.95,0,127.61,4885.56,4885.56,'20190422163515',''),
 ('DWAB1000000030','20190423164318','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',4885.56,0,371.6,5257.16,5257.16,'20190423164318',''),
 ('DWAB1000000031','20190423165437','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',5257.16,600,0,4657.16,4657.16,'20190423165437',''),
 ('DWAB1000000032','20190423223556','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',4657.16,68.9,0,4588.26,4588.26,'20190423223556',''),
 ('DWAB1000000033','20190426122446','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',4588.26,0,311.66,4899.92,4899.92,'20190426122446',''),
 ('DWAB1000000034','20190427024226','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',4899.92,0,264.9,5164.82,5164.82,'20190427024226',''),
 ('DWAB1000000035','20190427152030','ACCT1000000001','MAIN','Matador','Sales and Purchases amount should be Debited and Credited here',5164.82,0,117.28,5282.1,5282.1,'20190427152030','');
/*!40000 ALTER TABLE `day_wise_account_balance` ENABLE KEYS */;


--
-- Definition of table `expense_category`
--

DROP TABLE IF EXISTS `expense_category`;
CREATE TABLE `expense_category` (
  `category_id` varchar(25) NOT NULL,
  `category_name` varchar(40) NOT NULL,
  `description` varchar(100) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`category_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `expense_category`
--

/*!40000 ALTER TABLE `expense_category` DISABLE KEYS */;
INSERT INTO `expense_category` (`category_id`,`category_name`,`description`,`created`,`updated`) VALUES 
 ('EXPNCAT1000001','Tiffin','Expense for Tiffin','20190414163305','20190414163708'),
 ('EXPNCAT1000002','Lunch','Lunch','20190414172117',''),
 ('EXPNCAT1000003','Tea','Tea','20190414172200',''),
 ('EXPNCAT1000004','Breakfast','Breakfast','20190418111959',''),
 ('EXPNCAT1000005','Dinner','Dinner','20190418112012','');
/*!40000 ALTER TABLE `expense_category` ENABLE KEYS */;


--
-- Definition of table `expense_main`
--

DROP TABLE IF EXISTS `expense_main`;
CREATE TABLE `expense_main` (
  `expense_id` varchar(25) NOT NULL,
  `expense_type` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `owner_id` varchar(25) NOT NULL,
  `owner_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `company_id` varchar(25) default NULL,
  `company_name` varchar(100) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `expense_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`expense_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `expense_main`
--

/*!40000 ALTER TABLE `expense_main` DISABLE KEYS */;
INSERT INTO `expense_main` (`expense_id`,`expense_type`,`date_time`,`owner_id`,`owner_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`company_id`,`company_name`,`total_amount`,`order_status`,`expense_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('EXPN1000000001','Manual','20190416004258','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',660,'A','A','20190416004258','20190416102049','',''),
 ('EXPN1000000002','Manual','20190416015527','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',720,'A','A','20190416015527','20190416002730','',''),
 ('EXPN1000000003','Manual','20190416020713','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',240,'A','A','20190416020713','20190416020711','',''),
 ('EXPN1000000004','Manual','20190416022527','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',720,'A','A','20190416022527','20190416022524','',''),
 ('EXPN1000000005','Manual','20190416091937','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',160,'P','P','20190416091937','20190416104936','',''),
 ('EXPN1000000006','Manual','20190416104954','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',160,'A','A','20190416104954','20190420161805','',''),
 ('EXPN1000000007','Manual','20190416105436','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',80,'A','A','20190416105436','20190416112010','',''),
 ('EXPN1000000008','Manual','20190416112023','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',80,'A','C','20190416112023','20190416111111','',''),
 ('EXPN1000000009','Manual','20190416112804','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',5,'A','A','20190416112804','20190416111111','',''),
 ('EXPN1000000010','Manual','20190418112818','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','','',30,'A','A','20190418112818','20190420142913','',''),
 ('EXPN1000000011','Manual','20190418213041','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',23,'A','A','20190418213041','20190420142915','',''),
 ('EXPN1000000012','Manual','20190423165334','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',600,'A','A','20190423165334','20190423165331','','');
/*!40000 ALTER TABLE `expense_main` ENABLE KEYS */;


--
-- Definition of table `expense_product`
--

DROP TABLE IF EXISTS `expense_product`;
CREATE TABLE `expense_product` (
  `expense_product_id` varchar(25) NOT NULL,
  `expense_id` varchar(25) NOT NULL,
  `expense_type` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `category_id` varchar(25) NOT NULL,
  `category_name` varchar(100) NOT NULL,
  `quantity` int(11) NOT NULL,
  `price` double default NULL,
  `total_price` double default NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `expense_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`expense_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `expense_product`
--

/*!40000 ALTER TABLE `expense_product` DISABLE KEYS */;
INSERT INTO `expense_product` (`expense_product_id`,`expense_id`,`expense_type`,`date_time`,`category_id`,`category_name`,`quantity`,`price`,`total_price`,`discount_amt`,`total_amount`,`order_status`,`expense_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('EPDT1000000001','EXPN1000000001','Manual','20190416004258','EXPNCAT1000002','Lunch',8,80,640,60,580,'A','A','20190416011406','20190416002730','',''),
 ('EPDT1000000002','EXPN1000000001','Manual','20190416004258','EXPNCAT1000003','Tea',8,10,80,0,80,'A','A','20190416011557','20190416002730','',''),
 ('EPDT1000000003','EXPN1000000002','Manual','20190416015527','EXPNCAT1000002','Lunch',8,80,640,0,640,'A','A','20190416015538','20190416002730','',''),
 ('EPDT1000000004','EXPN1000000002','Manual','20190416015527','EXPNCAT1000003','Tea',8,10,80,0,80,'A','A','20190416015555','20190416002730','',''),
 ('EPDT1000000005','EXPN1000000003','Manual','20190416020713','EXPNCAT1000002','Lunch',2,120,240,0,240,'A','A','20190416020724','20190416020711','',''),
 ('EPDT1000000006','EXPN1000000004','Manual','20190416022527','EXPNCAT1000002','Lunch',8,80,640,0,640,'A','A','20190416022539','20190416022524','',''),
 ('EPDT1000000007','EXPN1000000004','Manual','20190416022527','EXPNCAT1000003','Tea',8,10,80,0,80,'A','A','20190416022553','20190416022524','',''),
 ('EPDT1000000008','EXPN1000000005','Manual','20190416091937','EXPNCAT1000002','Lunch',2,80,160,0,160,'P','P','20190416092053','','',''),
 ('EPDT1000000009','EXPN1000000006','Manual','20190416104954','EXPNCAT1000002','Lunch',2,80,160,0,160,'A','A','20190416105003','20190416104530','',''),
 ('EPDT1000000010','EXPN1000000007','Manual','20190416105436','EXPNCAT1000003','Tea',8,10,80,0,80,'A','A','20190416105445','20190416111111','',''),
 ('EPDT1000000011','EXPN1000000008','Manual','20190416112023','EXPNCAT1000002','Lunch',1,80,80,0,80,'A','C','20190416112033','20190416111111','',''),
 ('EPDT1000000012','EXPN1000000009','Manual','20190416112804','EXPNCAT1000003','Tea',1,5,5,0,5,'A','A','20190416112814','20190416111111','',''),
 ('EPDT1000000013','EXPN1000000010','Manual','20190418112818','EXPNCAT1000004','Breakfast',1,30,30,0,30,'A','A','20190418112828','20190418111138','',''),
 ('EPDT1000000014','EXPN1000000011','Manual','20190418213041','EXPNCAT1000004','Breakfast',1,23,23,0,23,'A','A','20190418213050','20190418213026','',''),
 ('EPDT1000000015','EXPN1000000012','Manual','20190423165334','EXPNCAT1000002','Lunch',5,120,600,0,600,'A','A','20190423165344','20190423165331','','');
/*!40000 ALTER TABLE `expense_product` ENABLE KEYS */;


--
-- Definition of table `generic`
--

DROP TABLE IF EXISTS `generic`;
CREATE TABLE `generic` (
  `generic_id` varchar(25) NOT NULL,
  `generic_name` varchar(100) NOT NULL,
  `product_category_id` varchar(25) NOT NULL,
  `indications` text,
  `adult_dose` text,
  `child_dose` text,
  `renal_dose` text,
  `administrations` text,
  `contraindications` text,
  `side_effects` text,
  `precautions_warnings` text,
  `pregnancy_category` text,
  `therapeutic_class` text,
  `mode_of_action` text,
  `interaction` text,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`generic_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `generic`
--

/*!40000 ALTER TABLE `generic` DISABLE KEYS */;
INSERT INTO `generic` (`generic_id`,`generic_name`,`product_category_id`,`indications`,`adult_dose`,`child_dose`,`renal_dose`,`administrations`,`contraindications`,`side_effects`,`precautions_warnings`,`pregnancy_category`,`therapeutic_class`,`mode_of_action`,`interaction`,`created`,`updated`) VALUES 
 ('GENRIC10000001','Ball Pens','PRODCAT1000001','','','','','','','','','','','','','20190408230220',''),
 ('GENRIC10000002','gel pen','PRODCAT1000001','','','','','','','','','','','','','20190408230511','');
/*!40000 ALTER TABLE `generic` ENABLE KEYS */;


--
-- Definition of table `month_wise_account_balance`
--

DROP TABLE IF EXISTS `month_wise_account_balance`;
CREATE TABLE `month_wise_account_balance` (
  `month_wise_balance_id` varchar(25) NOT NULL,
  `month_balance` varchar(25) NOT NULL,
  `account_id` varchar(25) default NULL,
  `balance` double default NULL,
  `last_balance` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`month_wise_balance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `month_wise_account_balance`
--

/*!40000 ALTER TABLE `month_wise_account_balance` DISABLE KEYS */;
/*!40000 ALTER TABLE `month_wise_account_balance` ENABLE KEYS */;


--
-- Definition of table `monthly_sales`
--

DROP TABLE IF EXISTS `monthly_sales`;
CREATE TABLE `monthly_sales` (
  `sales_id` varchar(25) NOT NULL,
  `sales_type` varchar(25) NOT NULL,
  `salesman_id` varchar(25) default NULL,
  `salesman_name` varchar(40) default NULL,
  `date_time` varchar(14) default NULL,
  `product_id` varchar(25) default NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) default NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `from_account` varchar(25) default NULL,
  `to_account` varchar(25) default NULL,
  `account_id` varchar(25) default NULL,
  `total_amount` double default NULL,
  `last_day_amonut` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`sales_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `monthly_sales`
--

/*!40000 ALTER TABLE `monthly_sales` DISABLE KEYS */;
/*!40000 ALTER TABLE `monthly_sales` ENABLE KEYS */;


--
-- Definition of table `owner_info`
--

DROP TABLE IF EXISTS `owner_info`;
CREATE TABLE `owner_info` (
  `owner_id` varchar(25) NOT NULL,
  `owner_name` varchar(40) NOT NULL,
  `description` varchar(100) default NULL,
  `owner_type` varchar(1) default NULL,
  `owner_start_date` varchar(14) default NULL,
  `father_name` varchar(40) NOT NULL,
  `mother_name` varchar(40) default NULL,
  `nid` varchar(40) default NULL,
  `dob` varchar(25) default NULL,
  `occupation` varchar(40) default NULL,
  `country_id` varchar(25) default NULL,
  `mobile` varchar(40) NOT NULL,
  `email` varchar(200) default NULL,
  `account_id` varchar(25) default NULL,
  `home_address` varchar(200) NOT NULL,
  `office_address` varchar(200) default NULL,
  `profession` varchar(40) default NULL,
  `password` varchar(100) NOT NULL,
  `status` varchar(1) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `owner_info`
--

/*!40000 ALTER TABLE `owner_info` DISABLE KEYS */;
INSERT INTO `owner_info` (`owner_id`,`owner_name`,`description`,`owner_type`,`owner_start_date`,`father_name`,`mother_name`,`nid`,`dob`,`occupation`,`country_id`,`mobile`,`email`,`account_id`,`home_address`,`office_address`,`profession`,`password`,`status`,`created`,`updated`) VALUES 
 ('OWNR1000000001','Matador','Matador','I','20190414075609','Matador','Matador','20190217155348','19880101','','BD','01815228050','matador@gmail.com','ACCT1000000001','Savar','New Market','Business Man','81dc9bdb52d04dc20036dbd8313ed055','A','20190414075609','20190420151212');
/*!40000 ALTER TABLE `owner_info` ENABLE KEYS */;


--
-- Definition of table `pack_piceces`
--

DROP TABLE IF EXISTS `pack_piceces`;
CREATE TABLE `pack_piceces` (
  `pack_piceces_id` varchar(25) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`pack_piceces_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `pack_piceces`
--

/*!40000 ALTER TABLE `pack_piceces` DISABLE KEYS */;
INSERT INTO `pack_piceces` (`pack_piceces_id`,`pack_type`,`pack_size`,`piceces`,`created`,`updated`) VALUES 
 ('PAKPCES1000001','box','1',60,'20190225004831',''),
 ('PAKPCES1000002','box','1',20,'20190225004847',''),
 ('PAKPCES1000003','box','1',30,'20190225004856',''),
 ('PAKPCES1000004','box','1',100,'20190225004903',''),
 ('PAKPCES1000005','strip','1',10,'20190311141957','20190311142114'),
 ('PAKPCES1000006','strip','1',6,'20190408230856',''),
 ('PAKPCES1000007','strip','1',12,'20190408232329','');
/*!40000 ALTER TABLE `pack_piceces` ENABLE KEYS */;


--
-- Definition of table `payment`
--

DROP TABLE IF EXISTS `payment`;
CREATE TABLE `payment` (
  `payment_id` varchar(25) NOT NULL,
  `payment_type` varchar(25) NOT NULL,
  `payment_desc` varchar(200) default NULL,
  `payment_date` varchar(14) NOT NULL,
  `account_id` varchar(25) default NULL,
  `from_account` varchar(25) default NULL,
  `to_account` varchar(25) default NULL,
  `amount` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`payment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `payment`
--

/*!40000 ALTER TABLE `payment` DISABLE KEYS */;
/*!40000 ALTER TABLE `payment` ENABLE KEYS */;


--
-- Definition of table `point_details`
--

DROP TABLE IF EXISTS `point_details`;
CREATE TABLE `point_details` (
  `point_id` varchar(25) NOT NULL,
  `point` varchar(40) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_point` varchar(40) default NULL,
  `description` varchar(200) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`point_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `point_details`
--

/*!40000 ALTER TABLE `point_details` DISABLE KEYS */;
/*!40000 ALTER TABLE `point_details` ENABLE KEYS */;


--
-- Definition of table `product`
--

DROP TABLE IF EXISTS `product`;
CREATE TABLE `product` (
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `product_type_id` varchar(25) NOT NULL,
  `product_type` varchar(40) NOT NULL,
  `stength` varchar(40) NOT NULL,
  `brand_id` varchar(25) NOT NULL,
  `brand_name` varchar(100) NOT NULL,
  `product_category_id` varchar(25) NOT NULL,
  `product_category_name` varchar(40) NOT NULL,
  `generic_id` varchar(25) NOT NULL,
  `generic_name` varchar(100) NOT NULL,
  `pack_piceces_id` varchar(25) default NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) default NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `tp_price` double default NULL,
  `mrp_price` double default NULL,
  `total_tp_price` double default NULL,
  `total_mrp_price` double default NULL,
  `stock` varchar(25) default NULL,
  `bonus_id` varchar(25) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `company_id` varchar(25) NOT NULL,
  `company_name` varchar(100) NOT NULL,
  PRIMARY KEY  (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `product`
--

/*!40000 ALTER TABLE `product` DISABLE KEYS */;
INSERT INTO `product` (`product_id`,`product_name`,`product_type_id`,`product_type`,`stength`,`brand_id`,`brand_name`,`product_category_id`,`product_category_name`,`generic_id`,`generic_name`,`pack_piceces_id`,`pack_type`,`pack_size`,`piceces`,`rate_per_piceces`,`rate_per_box`,`tp_price`,`mrp_price`,`total_tp_price`,`total_mrp_price`,`stock`,`bonus_id`,`created`,`updated`,`company_id`,`company_name`) VALUES 
 ('PROD1000000001','Matador High School .5 ball pen','PRDTYPE1000001','ball pen','.5','BRND1000000001','Matador High School','PRODCAT1000001','Pen','GENRIC10000001','Ball Pens','PAKPCES1000007','strip','1',12,5,60,3.68,3.92,44.16,47,'2668','','20190409110535','20190426122335','COMP1000000001','Matador'),
 ('PROD1000000002','Matador Radiant .5 ball pen','PRDTYPE1000001','ball pen','.5','BRND1000000002','Matador Radiant','PRODCAT1000001','Pen','GENRIC10000001','Ball Pens','PAKPCES1000006','strip','1',6,10,60,6.89,7.33,41.34,44,'2674','','20190409113012','20190427151259','COMP1000000001','Matador'),
 ('PROD1000000003','Matador Orbit .5 ball pen','PRDTYPE1000001','ball pen','.5','BRND1000000003','Matador Orbit','PRODCAT1000001','Pen','GENRIC10000001','','PAKPCES1000007','strip','1',12,5,60,3.68,3.92,44.16,47,'2449','','20190409113250','20190426122335','COMP1000000001','Matador'),
 ('PROD1000000004','Matador Radiant .5 gel pen','PRDTYPE1000002','gel pen','.5','BRND1000000002','Matador Radiant','PRODCAT1000001','Pen','GENRIC10000002','gel pen','PAKPCES1000001','box','1',60,8,480,7.2,7.63,432,457.92,'425','','20190417012757','20190427151259','COMP1000000001','Matador'),
 ('PROD1000000005','Matador i-teen .5 ball pen','PRDTYPE1000001','ball pen','.5','BRND1000000005','Matador i-teen','PRODCAT1000001','Pen','GENRIC10000001','Ball Pens','PAKPCES1000006','strip','1',6,10,60,6.89,7.33,41.34,44,'138','','20190419182632','20190427150859','COMP1000000001','Matador'),
 ('PROD1000000006','Matador Wood .5 ball pen','PRDTYPE1000001','ball pen','.5','BRND1000000006','Matador Wood','PRODCAT1000001','Pen','GENRIC10000001','Ball Pens','PAKPCES1000007','strip','1',12,10,120,8.33,8.83,100,106,'170','','20190427023929','20190427151259','COMP1000000001','Matador'),
 ('PROD1000000007','Matador Rio .5 ball pen','PRDTYPE1000001','ball pen','.5','BRND1000000007','Matador Rio','PRODCAT1000001','Pen','GENRIC10000001','Ball Pens','PAKPCES1000007','strip','1',12,10,120,8.7,9.25,104.4,111,'100','','20190427154531','','COMP1000000001','Matador');
/*!40000 ALTER TABLE `product` ENABLE KEYS */;


--
-- Definition of table `product_category`
--

DROP TABLE IF EXISTS `product_category`;
CREATE TABLE `product_category` (
  `product_category_id` varchar(25) NOT NULL,
  `product_category_name` varchar(40) NOT NULL,
  `description` varchar(200) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`product_category_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `product_category`
--

/*!40000 ALTER TABLE `product_category` DISABLE KEYS */;
INSERT INTO `product_category` (`product_category_id`,`product_category_name`,`description`,`created`,`updated`) VALUES 
 ('PRODCAT1000001','Pen','All Type of Pen','20190408230000',''),
 ('PRODCAT1000002','Pencil','All Type of Pencil','20190408230058',''),
 ('PRODCAT1000003','Note Book','All Type of Note Book','20190408230112',''),
 ('PRODCAT1000004','Marker','All Type of Marker','20190408230341',''),
 ('PRODCAT1000005','File','Plastic FIle','20190417010214','20190417012707');
/*!40000 ALTER TABLE `product_category` ENABLE KEYS */;


--
-- Definition of table `product_type`
--

DROP TABLE IF EXISTS `product_type`;
CREATE TABLE `product_type` (
  `product_type_id` varchar(25) NOT NULL,
  `product_type` varchar(40) NOT NULL,
  `stength` varchar(40) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`product_type_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `product_type`
--

/*!40000 ALTER TABLE `product_type` DISABLE KEYS */;
INSERT INTO `product_type` (`product_type_id`,`product_type`,`stength`,`created`,`updated`) VALUES 
 ('PRDTYPE1000001','ball pen','.5','20190408230425',''),
 ('PRDTYPE1000002','gel pen','.5','20190408230442','');
/*!40000 ALTER TABLE `product_type` ENABLE KEYS */;


--
-- Definition of table `profit_loss`
--

DROP TABLE IF EXISTS `profit_loss`;
CREATE TABLE `profit_loss` (
  `profit_loss_id` varchar(25) NOT NULL,
  `sales_id` varchar(25) NOT NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `total_sales_amount` double NOT NULL,
  `total_tp_price` double NOT NULL,
  `profit_amount` double NOT NULL,
  `profit_percent` varchar(25) default NULL,
  `loss_amount` double NOT NULL,
  `loss_percent` varchar(25) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`profit_loss_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `profit_loss`
--

/*!40000 ALTER TABLE `profit_loss` DISABLE KEYS */;
INSERT INTO `profit_loss` (`profit_loss_id`,`sales_id`,`from_account_id`,`to_account_id`,`total_sales_amount`,`total_tp_price`,`profit_amount`,`profit_percent`,`loss_amount`,`loss_percent`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('PFLS1000000001','SALS1000000001','ACCT1000000001','',1960,1840,120,'6.52 %',0,'0 %','20190409111139','','',''),
 ('PFLS1000000002','SALS1000000002','ACCT1000000001','',303.4,285,18.4,'6.46 %',0,'0 %','20190409113552','','',''),
 ('PFLS1000000003','SALS1000000003','ACCT1000000001','',196,184,12,'6.52 %',0,'0 %','20190409160026','','',''),
 ('PFLS1000000004','SALS1000000004','ACCT1000000001','',1466,1378,88,'6.39 %',0,'0 %','20190410000116','','',''),
 ('PFLS1000000005','SALS1000000005','ACCT1000000001','',782.4,735.2,47.1999999999999,'6.42 %',0,'0 %','20190414190830','','',''),
 ('PFLS1000000006','SALS1000000006','ACCT1000000001','',709.1,666.3,42.8000000000001,'6.42 %',0,'0 %','20190416021731','','',''),
 ('PFLS1000000007','SALS1000000007','ACCT1000000001','',2744,2576,168,'6.52 %',0,'0 %','20190416022836','','',''),
 ('PFLS1000000008','SALS1000000009','ACCT1000000001','',1125,1057,68,'6.43 %',0,'0 %','20190419194323','','',''),
 ('PFLS1000000009','SALS1000000010','ACCT1000000001','',366.5,344.5,22,'6.39 %',0,'0 %','20190420035627','','',''),
 ('PFLS1000000010','SALS1000000012','ACCT1000000001','',219.9,206.7,13.2,'6.39 %',0,'0 %','20190420050006','','',''),
 ('PFLS1000000011','SALS1000000013','ACCT1000000001','',366.5,344.5,22,'6.39 %',0,'0 %','20190420050222','','',''),
 ('PFLS1000000012','SALS1000000014','ACCT1000000001','',196,184,12,'6.52 %',0,'0 %','20190421112558','','',''),
 ('PFLS1000000013','SALS1000000015','ACCT1000000001','',366.5,344.5,22,'6.39 %',0,'0 %','20190421121518','','',''),
 ('PFLS1000000014','SALS1000000017','ACCT1000000001','',748,704.5,43.5,'6.17 %',0,'0 %','20190421145311','','',''),
 ('PFLS1000000015','SALS1000000018','ACCT1000000001','',11.25,10.57,0.68,'6.43 %',0,'0 %','20190422162317','','',''),
 ('PFLS1000000016','SALS1000000019','ACCT1000000001','',127.61,120.23,7.38,'6.14 %',0,'0 %','20190422163515','','',''),
 ('PFLS1000000017','SALS1000000020','ACCT1000000001','',371.6,349.2,22.4,'6.41 %',0,'0 %','20190423164318','','',''),
 ('PFLS1000000018','SALS1000000021','ACCT1000000001','',311.66,293.25,18.41,'6.28 %',0,'0 %','20190426122446','','',''),
 ('PFLS1000000019','SALS1000000022','ACCT1000000001','',264.9,249.9,15,'6.0 %',0,'0 %','20190427024226','','',''),
 ('PFLS1000000020','SALS1000000023','ACCT1000000001','',117.28,110.24,7.04,'6.39 %',0,'0 %','20190427152030','','','');
/*!40000 ALTER TABLE `profit_loss` ENABLE KEYS */;


--
-- Definition of table `purchase`
--

DROP TABLE IF EXISTS `purchase`;
CREATE TABLE `purchase` (
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) default NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `tp_price` double default NULL,
  `total_tp_price` double default NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`purchase_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `purchase`
--

/*!40000 ALTER TABLE `purchase` DISABLE KEYS */;
/*!40000 ALTER TABLE `purchase` ENABLE KEYS */;


--
-- Definition of table `purchase_main`
--

DROP TABLE IF EXISTS `purchase_main`;
CREATE TABLE `purchase_main` (
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `owner_id` varchar(25) NOT NULL,
  `owner_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `company_id` varchar(25) default NULL,
  `company_name` varchar(100) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`purchase_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `purchase_main`
--

/*!40000 ALTER TABLE `purchase_main` DISABLE KEYS */;
INSERT INTO `purchase_main` (`purchase_id`,`purchase_type`,`date_time`,`owner_id`,`owner_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`company_id`,`company_name`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('PRCH1000000001','Manual','20190409110830','OWNR1000000001','Owner','01818327407','','ACCT1000000001','','COMP1000000001','Matador',1840,'A','D','20190409110830','20190420233453','',''),
 ('PRCH1000000003','Manual','20190411192513','CUST1000000007','Owner','01818327407','','ACCT1000000001','','COMP1000000001','Matador',528.5,'A','D','20190411192513','20190411192506','',''),
 ('PRCH1000000005','Manual','20190414075651','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',68.9,'A','D','20190414075651','20190423223129','',''),
 ('PRCH1000000007','Manual','20190419183541','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',1451.6,'A','D','20190419183541','20190419183537','',''),
 ('PRCH1000000008','Manual','20190420233558','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',344.5,'A','D','20190420233558','20190420233722','',''),
 ('PRCH1000000016','Manual','20190426210733','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',0,'P','P','20190426210733','','','');
/*!40000 ALTER TABLE `purchase_main` ENABLE KEYS */;


--
-- Definition of table `purchase_product`
--

DROP TABLE IF EXISTS `purchase_product`;
CREATE TABLE `purchase_product` (
  `purchase_product_id` varchar(25) NOT NULL,
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `tp_price` double default NULL,
  `total_tp_price` double default NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`purchase_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `purchase_product`
--

/*!40000 ALTER TABLE `purchase_product` DISABLE KEYS */;
INSERT INTO `purchase_product` (`purchase_product_id`,`purchase_id`,`purchase_type`,`date_time`,`product_id`,`product_name`,`pack_type`,`pack_size`,`piceces`,`bonus_id`,`bonus_name`,`rate_per_piceces`,`rate_per_box`,`order_pack`,`order_quantity`,`tp_price`,`total_tp_price`,`discount_amt`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('PPDT1000000001','PRCH1000000001','Manual','20190409110830','PROD1000000001','Matador High School .5 ball pen','strip','1',12,NULL,'',5,60,'',500,3.68,1840,0,1840,'A','D','','20190418005617','',''),
 ('PPDT1000000002','PRCH1000000003','Manual','20190411192513','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','',10,60,'',50,6.89,344.5,0,344.5,'A','D','20190411192533','20190411192506','',''),
 ('PPDT1000000003','PRCH1000000003','Manual','20190411192513','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',50,3.68,184,0,184,'A','D','20190411192605','20190411192506','',''),
 ('PPDT1000000004','PRCH1000000007','Manual','20190419183541','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','',10,60,'',200,6.89,1378,0,1378,'A','D','20190419183620','20190419183537','',''),
 ('PPDT1000000005','PRCH1000000007','Manual','20190419183541','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',20,3.68,73.6,0,73.6,'A','D','20190419192839','20190419183537','',''),
 ('PPDT1000000006','PRCH1000000008','Manual','20190420233558','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','',10,60,'',50,6.89,344.5,0,344.5,'A','D','20190420233607','20190420232748','',''),
 ('PPDT1000000007','PRCH1000000005','Manual','20190414075651','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','',10,60,'',10,6.89,68.9,0,68.9,'A','D','20190423223335','20190423223129','','');
/*!40000 ALTER TABLE `purchase_product` ENABLE KEYS */;


--
-- Definition of table `requisition`
--

DROP TABLE IF EXISTS `requisition`;
CREATE TABLE `requisition` (
  `requisition_id` varchar(25) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`requisition_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `requisition`
--

/*!40000 ALTER TABLE `requisition` DISABLE KEYS */;
/*!40000 ALTER TABLE `requisition` ENABLE KEYS */;


--
-- Definition of table `requisition_multi`
--

DROP TABLE IF EXISTS `requisition_multi`;
CREATE TABLE `requisition_multi` (
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`requisition_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `requisition_multi`
--

/*!40000 ALTER TABLE `requisition_multi` DISABLE KEYS */;
INSERT INTO `requisition_multi` (`requisition_id`,`date_time`,`customer_id`,`customer_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`salesman_id`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`) VALUES 
 ('REQU1000000010','20190418010159','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000001',366.5,'A','P','20190418010159','20190421105758'),
 ('REQU1000000011','20190418125317','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000002',0,'P','P','20190418125317','');
/*!40000 ALTER TABLE `requisition_multi` ENABLE KEYS */;


--
-- Definition of table `requisition_product`
--

DROP TABLE IF EXISTS `requisition_product`;
CREATE TABLE `requisition_product` (
  `requisition_product_id` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`requisition_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `requisition_product`
--

/*!40000 ALTER TABLE `requisition_product` DISABLE KEYS */;
INSERT INTO `requisition_product` (`requisition_product_id`,`requisition_id`,`date_time`,`product_id`,`product_name`,`pack_type`,`pack_size`,`piceces`,`bonus_id`,`bonus_name`,`order_pack`,`order_quantity`,`mrp_price`,`total_mrp_price`,`discount_amt`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`) VALUES 
 ('RPDT1000000001','REQU1000000010','20190418010159','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,NULL,'','',50,7.33,366.5,0,366.5,'A','P','20190418010209','20190418001313');
/*!40000 ALTER TABLE `requisition_product` ENABLE KEYS */;


--
-- Definition of table `sales`
--

DROP TABLE IF EXISTS `sales`;
CREATE TABLE `sales` (
  `sales_id` varchar(25) NOT NULL,
  `sales_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`sales_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sales`
--

/*!40000 ALTER TABLE `sales` DISABLE KEYS */;
/*!40000 ALTER TABLE `sales` ENABLE KEYS */;


--
-- Definition of table `sales_achievement`
--

DROP TABLE IF EXISTS `sales_achievement`;
CREATE TABLE `sales_achievement` (
  `sales_achievement_id` varchar(25) NOT NULL,
  `sales_achievement_type` varchar(25) NOT NULL,
  `salesman_id` varchar(25) default NULL,
  `salesman_name` varchar(40) default NULL,
  `last_day_achievement` double default NULL,
  `last_day_achievement_percent` double default NULL,
  `day_achievement` double default NULL,
  `day_achievement_percent` double default NULL,
  `last_month_achievement` double default NULL,
  `last_month_achievement_percent` double default NULL,
  `month_achievement` double default NULL,
  `month_achievement_percent` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`sales_achievement_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sales_achievement`
--

/*!40000 ALTER TABLE `sales_achievement` DISABLE KEYS */;
/*!40000 ALTER TABLE `sales_achievement` ENABLE KEYS */;


--
-- Definition of table `sales_main`
--

DROP TABLE IF EXISTS `sales_main`;
CREATE TABLE `sales_main` (
  `sales_id` varchar(25) NOT NULL,
  `sales_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `customer_id` varchar(25) NOT NULL,
  `customer_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `salesman_id` varchar(25) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`sales_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sales_main`
--

/*!40000 ALTER TABLE `sales_main` DISABLE KEYS */;
INSERT INTO `sales_main` (`sales_id`,`sales_type`,`requisition_id`,`date_time`,`customer_id`,`customer_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`salesman_id`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('SALS1000000001','Requisition','REQU1000000001','20190409111059','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000002',1960,'S','D','20190409111059','20190409111132','',''),
 ('SALS1000000002','Requisition','REQU1000000001','20190409113439','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',303.4,'S','D','20190409113439','20190409111132','',''),
 ('SALS1000000003','Requisition','REQU1000000004','20190409155210','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000001',196,'S','D','20190409155210','20190409153950','',''),
 ('SALS1000000004','Requisition','REQU1000000005','20190409233150','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',1466,'S','D','20190409233150','20190418010651','',''),
 ('SALS1000000005','Requisition','REQU1000000007','20190414190540','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000001',782.4,'S','D','20190414190540','20190414190734','',''),
 ('SALS1000000006','Requisition','REQU1000000008','20190415130912','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',709.1,'S','D','20190415130912','20190416021722','',''),
 ('SALS1000000007','Requisition','REQU1000000009','20190416022748','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',2744,'S','D','20190416022748','20190416022829','',''),
 ('SALS1000000008','Requisition','REQU1000000010','20190418010159','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000001',366.5,'S','P','20190418010159','20190418111750','',''),
 ('SALS1000000009','Manual','REQU1000000012','20190419193206','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',1125,'S','D','20190419193206','20190419193202','',''),
 ('SALS1000000010','Manual','REQU1000000012','20190419195037','CUST1000000004','Test User','01818888888','','ACCT1000000001','','SMAN1000000002',366.5,'S','D','20190419195037','20190420035450','',''),
 ('SALS1000000011','Manual','REQU1000000013','20190420035905','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000001',366.5,'A','P','20190420035905','20190420035929','',''),
 ('SALS1000000012','Manual','REQU1000000014','20190420045918','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',219.9,'S','D','20190420045918','20190420045915','',''),
 ('SALS1000000013','Manual','REQU1000000015','20190420050117','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000002',366.5,'S','D','20190420050117','20190422060936','',''),
 ('SALS1000000014','Requisition','REQU1000000016','20190421000622','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',196,'S','D','20190421000622','20190421112333','',''),
 ('SALS1000000015','Manual','REQU1000000017','20190421121139','CUST1000000002','Sumon','01683804300','','ACCT1000000001','','SMAN1000000001',366.5,'S','D','20190421121139','20190421121131','',''),
 ('SALS1000000016','Manual','REQU1000000019','20190421130249','CUST1000000003','Nayem Shihab Uddin Noor','01613600471','','ACCT1000000001','','SMAN1000000001',366.5,'C','P','20190421130249','20190422060901','',''),
 ('SALS1000000017','Manual','REQU1000000020','20190421144231','CUST1000000005','Mohiuddin Mithu','01815228050','','ACCT1000000001','','SMAN1000000001',748,'S','D','20190421144231','20190422054650','',''),
 ('SALS1000000018','Manual','REQU1000000021','20190422060245','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',11.25,'S','D','20190422060245','20190422161918','',''),
 ('SALS1000000019','Manual','REQU1000000023','20190422162433','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',127.61,'S','D','20190422162433','20190422161918','',''),
 ('SALS1000000020','Manual','REQU1000000024','20190423163714','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000001',371.6,'S','D','20190423163714','20190423163648','',''),
 ('SALS1000000021','Manual','REQU1000000027','20190426122338','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000002',311.66,'S','D','20190426122338','20190426210811','',''),
 ('SALS1000000022','Manual','REQU1000000028','20190427024142','CUST1000000001','K.M. Rashedul Islam','01818327407','','ACCT1000000001','','SMAN1000000002',264.9,'S','D','20190427024142','20190427024139','',''),
 ('SALS1000000023','Manual','REQU1000000029','20190427151106','CUST1000000006','Tasnim Jahan Rojoni Athoy','01673376181','','ACCT1000000001','','SMAN1000000002',117.28,'S','D','20190427151106','20190427150859','','');
/*!40000 ALTER TABLE `sales_main` ENABLE KEYS */;


--
-- Definition of table `sales_product`
--

DROP TABLE IF EXISTS `sales_product`;
CREATE TABLE `sales_product` (
  `sales_product_id` varchar(25) NOT NULL,
  `sales_id` varchar(25) NOT NULL,
  `sales_type` varchar(25) NOT NULL,
  `requisition_product_id` varchar(25) NOT NULL,
  `requisition_id` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `mrp_price` double NOT NULL,
  `total_mrp_price` double NOT NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`sales_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sales_product`
--

/*!40000 ALTER TABLE `sales_product` DISABLE KEYS */;
INSERT INTO `sales_product` (`sales_product_id`,`sales_id`,`sales_type`,`requisition_product_id`,`requisition_id`,`date_time`,`product_id`,`product_name`,`pack_type`,`pack_size`,`piceces`,`bonus_id`,`bonus_name`,`order_pack`,`order_quantity`,`mrp_price`,`total_mrp_price`,`discount_amt`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('SPDT1000000001','SALS1000000001','Requisition','RPDT1000000001','REQU1000000001','20190409111059','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',500,3.92,1960,0,1960.55,'S','D','20190409111113','20190409111132','',''),
 ('SPDT1000000002','SALS1000000002','Requisition','RPDT1000000001','REQU1000000001','20190409113439','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',20,3.92,78.4,0,78.4,'S','D','20190409113453','20190409111132','',''),
 ('SPDT1000000003','SALS1000000002','Requisition','RPDT1000000002','REQU1000000001','20190409113439','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',20,7.33,146.6,0,146.6,'S','D','20190409113505','20190409111132','',''),
 ('SPDT1000000004','SALS1000000002','Requisition','RPDT1000000003','REQU1000000001','20190409113439','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',20,3.92,78.4,0,78.4,'S','D','20190409113520','20190409111132','',''),
 ('SPDT1000000005','SALS1000000003','Requisition','RPDT1000000001','REQU1000000004','20190409155210','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190409155446','20190409153950','',''),
 ('SPDT1000000006','SALS1000000004','sales_type','RPDT1000000001','REQU1000000005','20190409233150','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,NULL,'','',200,7.33,1466,0,1466,'S','D','20190410000040','20190418010652','',''),
 ('SPDT1000000007','SALS1000000005','Requisition','RPDT1000000001','REQU1000000007','20190414190540','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190414190603','20190414190734','',''),
 ('SPDT1000000008','SALS1000000005','Requisition','RPDT1000000002','REQU1000000007','20190414190540','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',80,7.33,586.4,0,586.4,'S','D','20190414190641','20190414190734','',''),
 ('SPDT1000000009','SALS1000000006','Requisition','RPDT1000000001','REQU1000000008','20190415130912','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190415130924','20190416021722','',''),
 ('SPDT1000000010','SALS1000000006','Requisition','RPDT1000000002','REQU1000000008','20190415130912','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190415152710','20190416021722','',''),
 ('SPDT1000000011','SALS1000000006','Requisition','RPDT1000000003','REQU1000000008','20190415130912','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',20,7.33,146.6,0,146.6,'S','D','20190415152750','20190416021722','',''),
 ('SPDT1000000012','SALS1000000007','Requisition','RPDT1000000001','REQU1000000009','20190416022748','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',200,3.92,784,0,784,'S','D','20190416022758','20190416022829','',''),
 ('SPDT1000000013','SALS1000000007','Requisition','RPDT1000000002','REQU1000000009','20190416022748','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',500,3.92,1960,0,1960,'S','D','20190416022813','20190416022829','',''),
 ('SPDT1000000014','SALS1000000008','Requisition','RPDT1000000001','REQU1000000010','20190418010159','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,NULL,'','',50,7.33,366.5,0,366.5,'S','P','20190418010209','20190418111750','',''),
 ('SPDT1000000015','SALS1000000009','sales_type','RPDT1000000002','REQU1000000012','20190419193206','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',100,7.33,733,0,733,'S','D','20190419193249','20190419193202','',''),
 ('SPDT1000000016','SALS1000000009','sales_type','RPDT1000000002','REQU1000000012','20190419193206','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190419193407','20190419193202','',''),
 ('SPDT1000000017','SALS1000000009','sales_type','RPDT1000000002','REQU1000000012','20190419193206','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,NULL,'','',50,3.92,196,0,196,'S','D','20190419193437','20190419193202','',''),
 ('SPDT1000000018','SALS1000000010','sales_type','RPDT1000000002','REQU1000000012','20190419195037','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190419195046','20190420035450','',''),
 ('SPDT1000000019','SALS1000000011','sales_type','RPDT1000000002','REQU1000000012','20190420035905','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'A','P','20190420035929','','',''),
 ('SPDT1000000020','SALS1000000012','sales_type','RPDT1000000002','REQU1000000014','20190420045918','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',30,7.33,219.9,0,219.9,'S','D','20190420045930','20190420045915','',''),
 ('SPDT1000000021','SALS1000000013','sales_type','RPDT1000000002','REQU1000000015','20190420050117','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190420050125','20190420050114','',''),
 ('SPDT1000000022','SALS1000000014','Requisition','RPDT1000000002','REQU1000000016','20190421000622','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',50,3.92,196,0,196,'S','D','20190421000632','20190421112333','',''),
 ('SPDT1000000023','SALS1000000015','sales_type','RPDT1000000002','REQU1000000017','20190421121139','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190421121157','20190421121131','',''),
 ('SPDT1000000024','SALS1000000016','sales_type','RPDT1000000002','REQU1000000019','20190421130249','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'A','P','20190421130301','','',''),
 ('SPDT1000000025','SALS1000000017','Manual','RPDT1000000002','REQU1000000020','20190421144231','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',50,7.33,366.5,0,366.5,'S','D','20190421144301','20190421144812','',''),
 ('SPDT1000000027','SALS1000000017','Manual','RPDT1000000002','REQU1000000020','20190421144231','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','','',50,7.63,381.5,0,381.5,'S','D','20190421144844','20190421144812','',''),
 ('SPDT1000000028','SALS1000000018','Manual','RPDT1000000002','REQU1000000021','20190422060245','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'','',1,7.33,7.33,0,7.33,'S','D','20190422060257','20190422161918','',''),
 ('SPDT1000000029','SALS1000000018','Manual','RPDT1000000002','REQU1000000021','20190422060245','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,NULL,'','',1,3.92,3.92,0,3.92,'S','D','20190422061450','20190422161918','',''),
 ('SPDT1000000030','SALS1000000019','Manual','RPDT1000000002','REQU1000000023','20190422162433','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'','',7,7.33,51.31,0,51.31,'S','D','20190422162448','20190422161918','',''),
 ('SPDT1000000031','SALS1000000019','Manual','RPDT1000000002','REQU1000000023','20190422162433','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,NULL,'','',10,7.63,76.3,0,76.3,'S','D','20190422162738','20190422161918','',''),
 ('SPDT1000000032','SALS1000000020','Manual','RPDT1000000002','REQU1000000024','20190423163714','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'','',40,7.33,293.2,0,293.2,'S','D','20190423163746','20190423163648','',''),
 ('SPDT1000000033','SALS1000000020','Manual','RPDT1000000002','REQU1000000024','20190423163714','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',20,3.92,78.4,0,78.4,'S','D','20190423163839','20190423163648','',''),
 ('SPDT1000000034','SALS1000000021','Manual','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','','',15,7.63,114.45,0,114.45,'S','D','20190426122345','20190426122335','',''),
 ('SPDT1000000035','SALS1000000021','Manual','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',13,7.33,95.29,0,95.29,'S','D','20190426122401','20190426122335','',''),
 ('SPDT1000000036','SALS1000000021','Manual','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','','',12,3.92,47.04,0,47.04,'S','D','20190426122411','20190426122335','',''),
 ('SPDT1000000037','SALS1000000021','Manual','RPDT1000000002','REQU1000000027','20190426122338','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','','',14,3.92,54.88,0,54.88,'S','D','20190426122422','20190426122335','',''),
 ('SPDT1000000038','SALS1000000022','Manual','RPDT1000000002','REQU1000000028','20190427024142','PROD1000000006','Matador Wood .5 ball pen','strip','1',12,'','','',30,8.83,264.9,0,264.9,'S','D','20190427024155','20190427024139','',''),
 ('SPDT1000000040','SALS1000000023','Manual','RPDT1000000002','REQU1000000029','20190427151106','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','','',10,7.33,73.3,0,73.3,'S','D','20190427151402','20190427150859','',''),
 ('SPDT1000000042','SALS1000000023','Manual','RPDT1000000002','REQU1000000029','20190427151106','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,NULL,'','',6,7.33,43.98,0,43.98,'S','D','20190427151536','20190427150859','','');
/*!40000 ALTER TABLE `sales_product` ENABLE KEYS */;


--
-- Definition of table `sales_rate`
--

DROP TABLE IF EXISTS `sales_rate`;
CREATE TABLE `sales_rate` (
  `sales_rate_id` varchar(25) NOT NULL,
  `rate_percent` double NOT NULL,
  `description` varchar(200) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`sales_rate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sales_rate`
--

/*!40000 ALTER TABLE `sales_rate` DISABLE KEYS */;
INSERT INTO `sales_rate` (`sales_rate_id`,`rate_percent`,`description`,`created`,`updated`,`created_by`,`updated_by`) VALUES 
 ('SalesRate10001',6,'Six percent profit','20190427154450','','','');
/*!40000 ALTER TABLE `sales_rate` ENABLE KEYS */;


--
-- Definition of table `sales_target`
--

DROP TABLE IF EXISTS `sales_target`;
CREATE TABLE `sales_target` (
  `sales_target_id` varchar(25) NOT NULL,
  `sales_target_type` varchar(25) NOT NULL,
  `sales_target_day` varchar(14) default NULL,
  `sales_target_month` varchar(14) default NULL,
  `salesman_id` varchar(25) default NULL,
  `salesman_name` varchar(40) default NULL,
  `last_day_target` double default NULL,
  `last_day_target_percent` double default NULL,
  `day_target` double default NULL,
  `day_target_percent` double default NULL,
  `last_month_target` double default NULL,
  `last_month_target_percent` double default NULL,
  `month_target` double default NULL,
  `month_target_percent` double default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`sales_target_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `sales_target`
--

/*!40000 ALTER TABLE `sales_target` DISABLE KEYS */;
/*!40000 ALTER TABLE `sales_target` ENABLE KEYS */;


--
-- Definition of table `salesman_info`
--

DROP TABLE IF EXISTS `salesman_info`;
CREATE TABLE `salesman_info` (
  `salesman_id` varchar(25) NOT NULL,
  `salesman_name` varchar(40) NOT NULL,
  `salesman_desc` varchar(40) default NULL,
  `salesman_type` varchar(25) default NULL,
  `salesman_start_date` varchar(14) default NULL,
  `salesman_position` varchar(40) default NULL,
  `father_name` varchar(40) NOT NULL,
  `mother_name` varchar(40) NOT NULL,
  `nid` varchar(25) NOT NULL,
  `dob` varchar(14) NOT NULL,
  `occupation` varchar(40) default NULL,
  `home_address` varchar(200) NOT NULL,
  `office_address` varchar(200) default NULL,
  `country_id` varchar(25) default NULL,
  `mobile` varchar(25) NOT NULL,
  `email` varchar(200) default NULL,
  `account_id` varchar(25) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `status` varchar(1) NOT NULL,
  PRIMARY KEY  (`salesman_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `salesman_info`
--

/*!40000 ALTER TABLE `salesman_info` DISABLE KEYS */;
INSERT INTO `salesman_info` (`salesman_id`,`salesman_name`,`salesman_desc`,`salesman_type`,`salesman_start_date`,`salesman_position`,`father_name`,`mother_name`,`nid`,`dob`,`occupation`,`home_address`,`office_address`,`country_id`,`mobile`,`email`,`account_id`,`created`,`updated`,`status`) VALUES 
 ('SMAN1000000001','K.M. Rashedul Islam','K.M. Rashedul Islam','Permanent','20190314234600','Salesman','Ali Ahammed','Rashida Sultana','20190217155348','19880101','Play Cricket, Football','Mirpur - 12','Niketon','BD','01818327407','rashedul@icliquebd.com','','20190314234600','20190314235005','A'),
 ('SMAN1000000002','Nayem Shihab Uddin Noor','Nayem Shihab Uddin Noor','Permanent','20190315003302','Salesman','Noor','Mrs Noor','20190217155348','19880101','Play Cricket, Football','Kazipara','Mohakhali','BD','01613600471','','','20190315003302','','A');
/*!40000 ALTER TABLE `salesman_info` ENABLE KEYS */;


--
-- Definition of table `state_city`
--

DROP TABLE IF EXISTS `state_city`;
CREATE TABLE `state_city` (
  `state_city_id` varchar(25) NOT NULL,
  `state_name` varchar(40) NOT NULL,
  `city_name` varchar(40) default NULL,
  `country_id` varchar(40) default NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  PRIMARY KEY  (`state_city_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `state_city`
--

/*!40000 ALTER TABLE `state_city` DISABLE KEYS */;
/*!40000 ALTER TABLE `state_city` ENABLE KEYS */;


--
-- Definition of table `transaction`
--

DROP TABLE IF EXISTS `transaction`;
CREATE TABLE `transaction` (
  `transaction_id` varchar(25) NOT NULL,
  `transaction_type` varchar(25) NOT NULL,
  `reason` varchar(100) default NULL,
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `requisition_id` varchar(25) default NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `tp_price` double default NULL,
  `total_tp_price` double default NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  PRIMARY KEY  (`transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `transaction`
--

/*!40000 ALTER TABLE `transaction` DISABLE KEYS */;
/*!40000 ALTER TABLE `transaction` ENABLE KEYS */;


--
-- Definition of table `transaction_main`
--

DROP TABLE IF EXISTS `transaction_main`;
CREATE TABLE `transaction_main` (
  `transaction_id` varchar(25) NOT NULL,
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `owner_id` varchar(25) NOT NULL,
  `owner_name` varchar(40) NOT NULL,
  `mobile` varchar(40) NOT NULL,
  `needed_date_time` varchar(14) default NULL,
  `from_account_id` varchar(25) default NULL,
  `to_account_id` varchar(25) default NULL,
  `company_id` varchar(25) default NULL,
  `company_name` varchar(100) default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  `reason` varchar(200) default NULL,
  PRIMARY KEY  (`transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `transaction_main`
--

/*!40000 ALTER TABLE `transaction_main` DISABLE KEYS */;
INSERT INTO `transaction_main` (`transaction_id`,`purchase_id`,`purchase_type`,`date_time`,`owner_id`,`owner_name`,`mobile`,`needed_date_time`,`from_account_id`,`to_account_id`,`company_id`,`company_name`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`,`reason`) VALUES 
 ('TRNX1000000001','PRCH1000000002','Manual','20190409224640','CUST1000000007','Owner','01818327407','','ACCT1000000001','','COMP1000000001','Matador',184,'A','R','20190409224640','20190409224602','','',''),
 ('TRNX1000000002','PRCH1000000004','Manual','20190414075125','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',184,'A','R','20190414075125','20190414074937','','',''),
 ('TRNX1000000003','PRCH1000000006','Manual','20190414075910','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',294.4,'A','R','20190414075910','20190414074937','','',''),
 ('TRNX1000000004','PRCH1000000010','Manual','20190423224111','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',68.9,'A','R','20190423224111','20190423231644','','',''),
 ('TRNX1000000005','PRCH1000000010','Manual','20190423224111','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',72,'A','R','20190423224111','20190423231922','','',''),
 ('TRNX1000000006','PRCH1000000010','Manual','20190423224111','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',0,'A','R','20190423224111','20190423231911','','',''),
 ('TRNX1000000007','PRCH1000000011','Manual','20190423233429','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',68.9,'A','R','20190423233429','20190423233427','','',''),
 ('TRNX1000000008','PRCH1000000011','Manual','20190423233429','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',18.4,'A','R','20190423233429','20190423233427','','',''),
 ('TRNX1000000009','PRCH1000000009','Manual','20190423164454','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',0,'A','R','20190423164454','20190423235131','','',''),
 ('TRNX1000000010','PRCH1000000010','Manual','20190423235140','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',41.34,'A','R','20190423235140','20190423235147','','',''),
 ('TRNX1000000011','PRCH1000000011','Manual','20190424011437','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',291.79,'A','R','20190424011437','20190424011428','','',''),
 ('TRNX1000000012','PRCH1000000012','Manual','20190424011711','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',33.12,'A','R','20190424011711','20190424011428','','',''),
 ('TRNX1000000013','PRCH1000000012','Manual','20190424011711','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',25.76,'A','R','20190424011711','20190424011448','','',''),
 ('TRNX1000000014','PRCH1000000012','Manual','20190424011711','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',68.9,'A','R','20190424011711','20190424013016','','',''),
 ('TRNX1000000015','PRCH1000000013','Manual','20190424014154','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',59.74,'A','R','20190424014154','20190424013106','','',''),
 ('TRNX1000000016','PRCH1000000013','Manual','20190424014154','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',124.7,'A','R','20190424014154','20190424013016','','',''),
 ('TRNX1000000017','PRCH1000000014','Manual','20190424021037','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',148.43,'A','R','20190424021037','20190424021031','','',''),
 ('TRNX1000000018','PRCH1000000015','Manual','20190424021529','OWNR1000000001','Matador','01815228050','','ACCT1000000001','','COMP1000000001','Matador',94.4,'A','R','20190424021529','20190424021031','','','');
/*!40000 ALTER TABLE `transaction_main` ENABLE KEYS */;


--
-- Definition of table `transaction_product`
--

DROP TABLE IF EXISTS `transaction_product`;
CREATE TABLE `transaction_product` (
  `transaction_product_id` varchar(25) NOT NULL,
  `transaction_id` varchar(25) NOT NULL,
  `purchase_product_id` varchar(25) NOT NULL,
  `purchase_id` varchar(25) NOT NULL,
  `purchase_type` varchar(25) NOT NULL,
  `date_time` varchar(14) NOT NULL,
  `product_id` varchar(25) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `pack_type` varchar(40) NOT NULL,
  `pack_size` varchar(25) default NULL,
  `piceces` int(11) NOT NULL,
  `bonus_id` varchar(25) default NULL,
  `bonus_name` varchar(40) default NULL,
  `rate_per_piceces` double default NULL,
  `rate_per_box` double default NULL,
  `order_pack` varchar(40) default NULL,
  `order_quantity` int(11) NOT NULL,
  `tp_price` double default NULL,
  `total_tp_price` double default NULL,
  `discount_amt` double default NULL,
  `total_amount` double NOT NULL,
  `order_status` varchar(1) NOT NULL,
  `delivery_status` varchar(1) NOT NULL,
  `created` varchar(14) default NULL,
  `updated` varchar(14) default NULL,
  `created_by` varchar(40) default NULL,
  `updated_by` varchar(40) default NULL,
  `reason` varchar(200) default NULL,
  PRIMARY KEY  (`transaction_product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `transaction_product`
--

/*!40000 ALTER TABLE `transaction_product` DISABLE KEYS */;
INSERT INTO `transaction_product` (`transaction_product_id`,`transaction_id`,`purchase_product_id`,`purchase_id`,`purchase_type`,`date_time`,`product_id`,`product_name`,`pack_type`,`pack_size`,`piceces`,`bonus_id`,`bonus_name`,`rate_per_piceces`,`rate_per_box`,`order_pack`,`order_quantity`,`tp_price`,`total_tp_price`,`discount_amt`,`total_amount`,`order_status`,`delivery_status`,`created`,`updated`,`created_by`,`updated_by`,`reason`) VALUES 
 ('TPDT1000000001','TRNX1000000001','PPDT1000000002','PRCH1000000002','Manual','20190409224640','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',50,3.68,184,0,184,'A','R','20190409224655','20190409224602','','',''),
 ('TPDT1000000002','TRNX1000000002','PPDT1000000004','PRCH1000000004','Manual','20190414075125','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',50,3.68,184,0,184,'A','R','20190414075137','20190414074937','','',''),
 ('TPDT1000000003','TRNX1000000003','PPDT1000000004','PRCH1000000006','Manual','20190414075910','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','',5,60,'',80,3.68,294.4,0,294.4,'A','R','20190414075918','20190414074937','','',''),
 ('TPDT1000000004','TRNX1000000007','PPDT1000000009','PRCH1000000011','Manual','20190423233429','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','',5,60,'',5,3.68,18.4,0,18.4,'A','R','20190423233448','20190423233427','','',''),
 ('TPDT1000000005','TRNX1000000011','PPDT1000000009','PRCH1000000011','Manual','20190424011437','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','',8,480,'',30,7.2,216,0,216,'A','R','20190424011448','20190424011428','','',''),
 ('TPDT1000000006','TRNX1000000011','PPDT1000000010','PRCH1000000011','Manual','20190424011437','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','',10,60,'',11,6.89,75.79,0,75.79,'A','R','20190424011505','20190424011428','','',''),
 ('TPDT1000000007','TRNX1000000012','PPDT1000000011','PRCH1000000012','Manual','20190424011711','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',9,3.68,33.12,0,33.12,'A','R','20190424011809','20190424011448','','',''),
 ('TPDT1000000008','TRNX1000000012','PPDT1000000010','PRCH1000000012','Manual','20190424011711','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','',5,60,'',7,3.68,25.76,0,25.76,'A','R','20190424011750','20190424011448','','',''),
 ('TPDT1000000009','TRNX1000000012','PPDT1000000009','PRCH1000000012','Manual','20190424011711','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'',10,60,'',10,6.89,68.9,0,68.9,'A','R','20190424011735','20190424013016','','',''),
 ('TPDT1000000010','TRNX1000000010','PPDT1000000008','PRCH1000000010','Manual','20190423235140','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',10,3.68,36.8,0,36.8,'A','R','20190423235147','20190424013016','','',''),
 ('TPDT1000000011','TRNX1000000015','PPDT1000000008','PRCH1000000013','Manual','20190424014154','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',5,3.68,18.4,0,18.4,'A','R','20190424014206','20190424013106','','',''),
 ('TPDT1000000012','TRNX1000000015','PPDT1000000009','PRCH1000000013','Manual','20190424014154','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','',10,60,'',6,6.89,41.34,0,41.34,'A','R','20190424014220','20190424013106','','',''),
 ('TPDT1000000013','TRNX1000000015','PPDT1000000010','PRCH1000000013','Manual','20190424014154','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','',5,60,'',7,3.68,25.76,0,25.76,'A','R','20190424014244','20190424013016','','',''),
 ('TPDT1000000014','TRNX1000000015','PPDT1000000011','PRCH1000000013','Manual','20190424014154','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','',8,480,'',8,7.2,57.6,0,57.6,'A','R','20190424014259','20190424013016','','',''),
 ('TPDT1000000015','TRNX1000000015','PPDT1000000012','PRCH1000000013','Manual','20190424014154','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,NULL,'',10,60,'',6,6.89,41.34,0,41.34,'A','R','20190424014311','20190424013016','','',''),
 ('TPDT1000000016','TRNX1000000017','PPDT1000000008','PRCH1000000014','Manual','20190424021037','PROD1000000001','Matador High School .5 ball pen','strip','1',12,'','',5,60,'',3,3.68,11.04,0,11.04,'A','R','20190424021052','20190424021048','','',''),
 ('TPDT1000000017','TRNX1000000017','PPDT1000000010','PRCH1000000014','Manual','20190424021037','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','',5,60,'',5,3.68,18.4,0,18.4,'A','R','20190424021122','20190424021048','','',''),
 ('TPDT1000000018','TRNX1000000017','PPDT1000000009','PRCH1000000014','Manual','20190424021037','PROD1000000002','Matador Radiant .5 ball pen','strip','1',6,'','',10,60,'',4,6.89,27.56,0,27.56,'A','R','20190424021109','20190424021031','','',''),
 ('TPDT1000000019','TRNX1000000017','PPDT1000000011','PRCH1000000014','Manual','20190424021037','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','',8,480,'',6,7.2,43.2,0,43.2,'A','R','20190424021143','20190424021031','','',''),
 ('TPDT1000000020','TRNX1000000017','PPDT1000000012','PRCH1000000014','Manual','20190424021037','PROD1000000005','Matador i-teen .5 ball pen','strip','1',6,'','',10,60,'',7,6.89,48.23,0,48.23,'A','R','20190424021200','20190424021031','','',''),
 ('TPDT1000000021','TRNX1000000018','PPDT1000000008','PRCH1000000015','Manual','20190424021529','PROD1000000003','Matador Orbit .5 ball pen','strip','1',12,'','',5,60,'',10,3.68,36.8,0,36.8,'A','R','20190424021538','20190424021031','','',''),
 ('TPDT1000000022','TRNX1000000018','PPDT1000000009','PRCH1000000015','Manual','20190424021529','PROD1000000004','Matador Radiant .5 gel pen','box','1',60,'','',8,480,'',8,7.2,57.6,0,57.6,'A','R','20190424021552','20190424021031','','','');
/*!40000 ALTER TABLE `transaction_product` ENABLE KEYS */;




/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
