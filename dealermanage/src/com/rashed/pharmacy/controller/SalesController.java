package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.dao.RequisitionDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.model.CustomerPurchase;
import com.rashed.pharmacy.dao.CustomerPurchaseDAO;
import com.rashed.pharmacy.model.CustomerTransaction;
import com.rashed.pharmacy.dao.CustomerTransactionDAO;
import com.rashed.pharmacy.model.Account;
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.model.DayWiseAccountBalance;
import com.rashed.pharmacy.dao.DayWiseAccountBalanceDAO;
import com.rashed.pharmacy.model.ProfitLoss;
import com.rashed.pharmacy.dao.ProfitLossDAO;
import com.rashed.pharmacy.util.*;

public class SalesController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/salesAdd.jsp";
	private static String LIST_SALES = "/jsp/order/salesList.jsp";
	private static String ENQUIRY = "/jsp/order/salesEnquiry.jsp";
	
	private RequisitionDAO rdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private SalesDAO sdao;
	private CustomerPurchaseDAO cpdao;
	private CustomerTransactionDAO ctdao;
	private AccountDAO adao;
	private DayWiseAccountBalanceDAO dwabdao;
	private ProfitLossDAO pldao;
	
	String action = "";
	String message = "";
	
       
    public SalesController() {
        super();
        rdao = new RequisitionDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        sdao = new SalesDAO();
        cpdao = new CustomerPurchaseDAO();
        ctdao = new CustomerTransactionDAO();
        adao = new AccountDAO();
        dwabdao = new DayWiseAccountBalanceDAO();
        pldao = new ProfitLossDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String sales_id = request.getParameter("sales_id");
			sdao.delete(sales_id);
			forward=LIST_SALES;
			request.setAttribute("saless", sdao.getAllSales());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("cancel")){
			String sales_id = request.getParameter("sales_id");
			String strOrderStatus = sdao.getSelectedOtherID(sales_id).getOrder_status();
			String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			String strRequisition = sdao.getSelectedOtherID(sales_id).getRequisition_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();
			
			if (!strOrderStatus.equals("S")) {
				sdao.cancel(sales_id);
				
				pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);
				
				message = "Sales " + sales_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Success Sales can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_SALES;
			request.setAttribute("saless", sdao.getAllSales());
		} else if(action.equalsIgnoreCase("approve")){
			String sales_id = request.getParameter("sales_id");
			String strOrderStatus = sdao.getSelectedOtherID(sales_id).getOrder_status();
			if (!strOrderStatus.equals("S") && !strOrderStatus.equals("C")) {
				sdao.approve(sales_id);
				message = "Sales " + sales_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Sales can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S")) {
					message = "Already Success !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_SALES;
			request.setAttribute("saless", sdao.getAllSales());
		} else if(action.equalsIgnoreCase("deliveryApprove")){
			String sales_id = request.getParameter("sales_id");
			String strOrderStatus = sdao.getSelectedOtherID(sales_id).getOrder_status();
			String strDeliveryStatus = sdao.getSelectedOtherID(sales_id).getDelivery_status();
			String strRequisition = sdao.getSelectedOtherID(sales_id).getRequisition_id();
			String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();
			String strFromAccount = sdao.getSelectedOtherID(sales_id).getFrom_account_id();
			String strToAccount = sdao.getSelectedOtherID(sales_id).getTo_account_id();
			double doubleTotalAmount = sdao.getSelectedOtherID(sales_id).getTotal_amount();

			if (strOrderStatus.equals("S") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C")) {
				sdao.deliveryApprove(sales_id);
				
				cpdao.salesToCustomerPurchase(sales_id);
				
				//ctdao.salesToCustomerTransaction(sales_id, action);
				
				adao.balanceUpdate(strFromAccount, doubleTotalAmount);
				// for insert data into day_wise_account_balance table [S]
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				dwabdao.dayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into day_wise_account_balance table [E]
				
				// for insert data into profit_loss table [S]
				pldao.profitLossAmount(sales_id, strFromAccount, doubleTotalAmount, strProduct, intOrderQuantity, strCurrentDateTime);
				// for insert data into profit_loss table [E]
				
				rdao.delete(strRequisition);
				
				//pdao.stockUpdate(strProduct, intOrderQuantity);
				
				message = "Sales " + sales_id + " Delivered Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Sales can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Sales can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Cancelled Delivered can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_SALES;
			request.setAttribute("saless", sdao.getAllSales());
		} else if(action.equalsIgnoreCase("deliveryReturn")){
			String sales_id = request.getParameter("sales_id");
			String strOrderStatus = sdao.getSelectedOtherID(sales_id).getOrder_status();
			String strDeliveryStatus = sdao.getSelectedOtherID(sales_id).getDelivery_status();
			String strRequisition = sdao.getSelectedOtherID(sales_id).getRequisition_id();
			String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();
			if (strOrderStatus.equals("S") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				sdao.deliveryReturn(sales_id);
				
				pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				//ctdao.salesToCustomerTransaction(sales_id);
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);
				
				message = "Sales " + sales_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Sales Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Sales can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Delivery Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("R")) {
					message = "Already Return !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_SALES;
			request.setAttribute("saless", sdao.getAllSales());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String sales_id = request.getParameter("sales_id");
			Sales s = sdao.getSalesById(sales_id);
			request.setAttribute("sales", s);
			// for get all the Requisition_id when update sales [S]
			request.setAttribute("allRequisition", rdao.getAllRequisition());
			// for get all the Requisition_id when update sales [E]
			// for get all the Product_id when update sales [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when update sales [E]
			// for get all the Customer when update sales [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when update sales [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedRequisitionId", sdao.getSelectedOtherID(sales_id).getRequisition_id());
			request.setAttribute("selectedCustomerId", sdao.getSelectedOtherID(sales_id).getCustomer_id());
			request.setAttribute("selectedProductId", sdao.getSelectedOtherID(sales_id).getProduct_id());
			request.setAttribute("selectedBonusId", sdao.getSelectedOtherID(sales_id).getBonus_id());
			request.setAttribute("selectedSalesmanId", sdao.getSelectedOtherID(sales_id).getSalesman_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("salesList")){
			forward = LIST_SALES;
			request.setAttribute("saless", sdao.getAllSales());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String sales_id = request.getParameter("sales_id");
			Sales s = sdao.getSalesById(sales_id);
			request.setAttribute("sales", s);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("salesId", sdao.getSalesID().getSales_id());
			// generated auto increment id during add [E]
			
			// for get all the Requisition_id when add sales [S]
			request.setAttribute("allRequisition", rdao.getAllRequisition());
			// for get all the Requisition_id when add sales [E]
			// for get all the Product_id when add sales [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when add sales [E]
			// for get all the Customer when add sales [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when add sales [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Sales s = new Sales();
		
		s.setSales_id(request.getParameter("sales_id"));
		s.setSales_type(request.getParameter("sales_type"));
		s.setRequisition_id(request.getParameter("requisition_id"));
		s.setCustomer_id(request.getParameter("customer_id"));
		s.setCustomer_name(request.getParameter("customer_name"));
		s.setMobile(request.getParameter("mobile"));
		s.setProduct_id(request.getParameter("product_id"));
		s.setProduct_name(request.getParameter("product_name"));
		s.setPack_type(request.getParameter("pack_type"));
		s.setPack_size(request.getParameter("pack_size"));
		s.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		s.setBonus_id(request.getParameter("bonus_id"));
		s.setBonus_name(request.getParameter("bonus_name"));
		s.setOrder_pack(request.getParameter("order_pack"));
		s.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		s.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		s.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		s.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		s.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		s.setNeeded_date_time(request.getParameter("needed_date_time"));
		s.setFrom_account_id(request.getParameter("from_account_id"));
		s.setTo_account_id(request.getParameter("to_account_id"));
		s.setSalesman_id(request.getParameter("salesman_id"));
		s.setOrder_status(request.getParameter("order_status"));
		s.setDelivery_status(request.getParameter("delivery_status"));
		s.setCreated(request.getParameter("created"));
		s.setUpdated(request.getParameter("updated"));
		s.setCreated_by(request.getParameter("created_by"));
		s.setUpdated_by(request.getParameter("updated_by"));
	
		String sales_id = request.getParameter("sales_id");

		if(action.equalsIgnoreCase("save")){
			sdao.save(s);
		} else if(action.equalsIgnoreCase("edit")){
			s.setSales_id(sales_id);
			sdao.update(s);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_SALES);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("saless", sdao.getAllSales());
		
		rd.forward(request, response);
	}

}
