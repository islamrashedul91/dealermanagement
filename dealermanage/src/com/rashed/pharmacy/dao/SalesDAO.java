package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.dao.RequisitionDAO;
import com.rashed.pharmacy.util.*;

public class SalesDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private RequisitionDAO rdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public SalesDAO(){
		//con  = DbUtil.getConnection();
		rdao = new RequisitionDAO();
	}
	
	
	public void save(Sales s){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO sales(sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales(sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, s.getSales_id());
			ps.setString(2, s.getSales_type());
			ps.setString(3, s.getRequisition_id());
			ps.setString(4, s.getCustomer_id());
			ps.setString(5, s.getCustomer_name());
			ps.setString(6, s.getMobile());
			ps.setString(7, s.getProduct_id());
			ps.setString(8, s.getProduct_name());
			ps.setString(9, s.getPack_type());
			ps.setString(10, s.getPack_size());
			ps.setInt(11, s.getPiceces());
			ps.setString(12, s.getBonus_id());
			ps.setString(13, s.getBonus_name());
			ps.setString(14, s.getOrder_pack());
			ps.setInt(15, s.getOrder_quantity());
			ps.setDouble(16, s.getMrp_price());
			ps.setDouble(17, s.getTotal_mrp_price());
			ps.setDouble(18, s.getDiscount_amt());
			ps.setDouble(19, s.getTotal_amount());
			ps.setString(20, s.getNeeded_date_time());
			ps.setString(21, s.getFrom_account_id());
			ps.setString(22, s.getTo_account_id());
			ps.setString(23, s.getSalesman_id());
			ps.setString(24, s.getOrder_status());
			ps.setString(25, s.getDelivery_status());
			ps.setString(26, s.getCreated());
			ps.setString(27, s.getUpdated());
			ps.setString(28, s.getCreated_by());
			ps.setString(29, s.getUpdated_by());
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void delete(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM sales WHERE sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM sales WHERE sales_id=?");
			
			ps.setString(1, sales_id);
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void cancel(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales set order_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales set order_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void approve(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales set order_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales set order_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "S");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void deliveryApprove(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales set delivery_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales set delivery_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "D");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void deliveryReturn(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales set delivery_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales set delivery_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void update(Sales s){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales set sales_type=?, requisition_id=?, customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales set sales_type=?, requisition_id=?, customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where sales_id=?");
			
			ps.setString(1, s.getSales_type());
			ps.setString(2, s.getRequisition_id());
			ps.setString(3, s.getCustomer_id());
			ps.setString(4, s.getCustomer_name());
			ps.setString(5, s.getMobile());
			ps.setString(6, s.getProduct_id());
			ps.setString(7, s.getProduct_name());
			ps.setString(8, s.getPack_type());
			ps.setString(9, s.getPack_size());
			ps.setInt(10, s.getPiceces());
			ps.setString(11, s.getBonus_id());
			ps.setString(12, s.getBonus_name());
			ps.setString(13, s.getOrder_pack());
			ps.setInt(14, s.getOrder_quantity());
			ps.setDouble(15, s.getMrp_price());
			ps.setDouble(16, s.getTotal_mrp_price());
			ps.setDouble(17, s.getDiscount_amt());
			ps.setDouble(18, s.getTotal_amount());
			ps.setString(19, s.getNeeded_date_time());
			ps.setString(20, s.getFrom_account_id());
			ps.setString(21, s.getTo_account_id());
			ps.setString(22, s.getSalesman_id());
			ps.setString(23, s.getOrder_status());
			ps.setString(24, s.getDelivery_status());
			ps.setString(25, s.getCreated());
			ps.setString(26, s.getUpdated());
			ps.setString(27, s.getCreated_by());
			ps.setString(28, s.getUpdated_by());
			ps.setString(29, s.getSales_id());
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public List<Sales> getAllSales(){
		List<Sales> list = new ArrayList<Sales>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM sales ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM sales ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Sales s = new Sales();				
				
				s.setSales_id(rs.getString(1));
				s.setSales_type(rs.getString(2));
				s.setRequisition_id(rs.getString(3));
				s.setCustomer_id(rs.getString(4));
				s.setCustomer_name(rs.getString(5));
				s.setMobile(rs.getString(6));
				s.setProduct_id(rs.getString(7));
				s.setProduct_name(rs.getString(8));
				s.setPack_type(rs.getString(9));
				s.setPack_size(rs.getString(10));
				s.setPiceces(rs.getInt(11));
				s.setBonus_id(rs.getString(12));
				s.setBonus_name(rs.getString(13));
				s.setOrder_pack(rs.getString(14));
				s.setOrder_quantity(rs.getInt(15));
				s.setMrp_price(rs.getDouble(16));
				s.setTotal_mrp_price(rs.getDouble(17));
				s.setDiscount_amt(rs.getDouble(18));
				s.setTotal_amount(rs.getDouble(19));
				s.setNeeded_date_time(rs.getString(20));
				s.setFrom_account_id(rs.getString(21));
				s.setTo_account_id(rs.getString(22));
				s.setSalesman_id(rs.getString(23));
				s.setOrder_status(rs.getString(24));
				s.setDelivery_status(rs.getString(25));
				s.setCreated(rs.getString(26));
				s.setUpdated(rs.getString(27));
				s.setCreated_by(rs.getString(28));
				s.setUpdated_by(rs.getString(29));
			
				list.add(s);				
			}
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return list;
	}
	
	public Sales getSalesById(String sales_id){
		Sales s = new Sales();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM sales where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM sales where sales_id=?");
			
			ps.setString(1, sales_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				s.setSales_id(rs.getString(1));
				s.setSales_type(rs.getString(2));
				s.setRequisition_id(rs.getString(3));
				s.setCustomer_id(rs.getString(4));
				s.setCustomer_name(rs.getString(5));
				s.setMobile(rs.getString(6));
				s.setProduct_id(rs.getString(7));
				s.setProduct_name(rs.getString(8));
				s.setPack_type(rs.getString(9));
				s.setPack_size(rs.getString(10));
				s.setPiceces(rs.getInt(11));
				s.setBonus_id(rs.getString(12));
				s.setBonus_name(rs.getString(13));
				s.setOrder_pack(rs.getString(14));
				s.setOrder_quantity(rs.getInt(15));
				s.setMrp_price(rs.getDouble(16));
				s.setTotal_mrp_price(rs.getDouble(17));
				s.setDiscount_amt(rs.getDouble(18));
				s.setTotal_amount(rs.getDouble(19));
				s.setNeeded_date_time(rs.getString(20));
				s.setFrom_account_id(rs.getString(21));
				s.setTo_account_id(rs.getString(22));
				s.setSalesman_id(rs.getString(23));
				s.setOrder_status(rs.getString(24));
				s.setDelivery_status(rs.getString(25));
				s.setCreated(rs.getString(26));
				s.setUpdated(rs.getString(27));
				s.setCreated_by(rs.getString(28));
				s.setUpdated_by(rs.getString(29));
				
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		} 

		return s;
	}
	
	// generated auto increment id during add [S]
	public Sales getSalesID(){
		Sales s = new Sales();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT sales_id FROM sales");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id FROM sales");
			
			rs = ps.executeQuery();
			
			int sales_id = 0;
			
			if(rs.next() == false) {
				sales_id = 1000000000;
				sales_id = sales_id+1;
				s.setSales_id("SALS" + String.valueOf(sales_id));
			} else {
				if(rs.last()) {
					String strSales = rs.getString("sales_id");
					sales_id = Integer.parseInt(strSales.replaceAll("[^0-9]", ""));
					sales_id = sales_id+1;
					s.setSales_id("SALS" + String.valueOf(sales_id));
				}
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return s;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public Sales getSelectedOtherID(String sales_id){
		Sales s = new Sales();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_id, requisition_id, customer_id, product_id, bonus_id, salesman_id, order_status, delivery_status, order_quantity, from_account_id, to_account_id, total_amount FROM sales WHERE sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, requisition_id, customer_id, product_id, bonus_id, salesman_id, order_status, delivery_status, order_quantity, from_account_id, to_account_id, total_amount FROM sales WHERE sales_id=?");
			
			ps.setString(1, sales_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strSales = rs.getString("sales_id");
				String strRequisition = rs.getString("requisition_id");
				String strCustomer = rs.getString("customer_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strSalesman = rs.getString("salesman_id");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				String strFromAccount = rs.getString("from_account_id");
				String strToAccount = rs.getString("to_account_id");
				double doubleTotalAmount = rs.getDouble("total_amount");
				
				s.setSales_id(strSales);
				s.setRequisition_id(strRequisition);
				s.setCustomer_id(strCustomer);
				s.setProduct_id(strProduct);
				s.setBonus_id(strBonus);
				s.setSalesman_id(strSalesman);
				s.setOrder_status(strOrderStatus);
				s.setDelivery_status(strDeliveryStatus);
				s.setOrder_quantity(intOrderQuantity);
				s.setFrom_account_id(strFromAccount);
				s.setTo_account_id(strToAccount);
				s.setTotal_amount(doubleTotalAmount);
				
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return s;
	}
	// selected other respective id during update [E]
	
	// after approve record copy from requisition to sales [S]
	public void requisitionToSales(String requisition_id){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO sales(sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales(sales_id, sales_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			//ps.setString(1, "1000000001");
			SalesDAO t = new SalesDAO();
			ps.setString(1, t.getSalesID().getSales_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, "Requisition");
			ps.setString(3, rdao.getRequisitionById(requisition_id).getRequisition_id());
			ps.setString(4, rdao.getRequisitionById(requisition_id).getCustomer_id());
			ps.setString(5, rdao.getRequisitionById(requisition_id).getCustomer_name());
			ps.setString(6, rdao.getRequisitionById(requisition_id).getMobile());
			ps.setString(7, rdao.getRequisitionById(requisition_id).getProduct_id());
			ps.setString(8, rdao.getRequisitionById(requisition_id).getProduct_name());
			ps.setString(9, rdao.getRequisitionById(requisition_id).getPack_type());
			ps.setString(10, rdao.getRequisitionById(requisition_id).getPack_size());
			ps.setInt(11, rdao.getRequisitionById(requisition_id).getPiceces());
			ps.setString(12, rdao.getRequisitionById(requisition_id).getBonus_id());
			ps.setString(13, rdao.getRequisitionById(requisition_id).getBonus_name());
			ps.setString(14, rdao.getRequisitionById(requisition_id).getOrder_pack());
			ps.setInt(15, rdao.getRequisitionById(requisition_id).getOrder_quantity());
			ps.setDouble(16, rdao.getRequisitionById(requisition_id).getMrp_price());
			ps.setDouble(17, rdao.getRequisitionById(requisition_id).getTotal_mrp_price());
			ps.setDouble(18, rdao.getRequisitionById(requisition_id).getDiscount_amt());
			ps.setDouble(19, rdao.getRequisitionById(requisition_id).getTotal_amount());
			ps.setString(20, rdao.getRequisitionById(requisition_id).getNeeded_date_time());
			ps.setString(21, rdao.getRequisitionById(requisition_id).getFrom_account_id());
			ps.setString(22, rdao.getRequisitionById(requisition_id).getTo_account_id());
			ps.setString(23, rdao.getRequisitionById(requisition_id).getSalesman_id());
			ps.setString(24, rdao.getRequisitionById(requisition_id).getOrder_status());
			ps.setString(25, rdao.getRequisitionById(requisition_id).getDelivery_status());
			ps.setString(26, rdao.getRequisitionById(requisition_id).getCreated());
			ps.setString(27, rdao.getRequisitionById(requisition_id).getUpdated());
			ps.setString(28, "");
			ps.setString(29, "");
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	// after approve record copy from requisition to sales [S]

}
