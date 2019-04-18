package com.rashed.pharmacy.controller;

import java.io.IOException;

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
import com.rashed.pharmacy.model.CustomerTransaction;
import com.rashed.pharmacy.dao.CustomerTransactionDAO;
import com.rashed.pharmacy.util.*;

public class CustomerTransactionController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/customerTransactionAdd.jsp";
	private static String LIST_CUSTOMERTRANSACTION = "/jsp/order/customerTransactionList.jsp";
	private static String ENQUIRY = "/jsp/order/customerTransactionEnquiry.jsp";
	
	private RequisitionDAO rdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private CustomerTransactionDAO ctdao;
	
	String action = "";
	String message = "";
	
       
    public CustomerTransactionController() {
        super();
        rdao = new RequisitionDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        ctdao = new CustomerTransactionDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String transaction_id = request.getParameter("transaction_id");
			ctdao.delete(transaction_id);
			forward=LIST_CUSTOMERTRANSACTION;
			request.setAttribute("customerTransactions", ctdao.getAllCustomerTransaction());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String transaction_id = request.getParameter("transaction_id");
			CustomerTransaction ct = ctdao.getCustomerTransactionById(transaction_id);
			request.setAttribute("customerTransaction", ct);
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
			request.setAttribute("selectedRequisitionId", ctdao.getSelectedOtherID(transaction_id).getRequisition_id());
			request.setAttribute("selectedCustomerId", ctdao.getSelectedOtherID(transaction_id).getCustomer_id());
			request.setAttribute("selectedProductId", ctdao.getSelectedOtherID(transaction_id).getProduct_id());
			request.setAttribute("selectedBonusId", ctdao.getSelectedOtherID(transaction_id).getBonus_id());
			request.setAttribute("selectedSalesmanId", ctdao.getSelectedOtherID(transaction_id).getSalesman_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("customerTransactionList")){
			forward = LIST_CUSTOMERTRANSACTION;
			request.setAttribute("customerTransactions", ctdao.getAllCustomerTransaction());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String transaction_id = request.getParameter("transaction_id");
			CustomerTransaction ct = ctdao.getCustomerTransactionById(transaction_id);
			request.setAttribute("customerTransaction", ct);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("transactionId", ctdao.getCustomerTransactionID().getTransaction_id());
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
		
		CustomerTransaction ct = new CustomerTransaction();
		
		ct.setTransaction_id(request.getParameter("transaction_id"));
		ct.setTransaction_type(request.getParameter("transaction_type"));
		ct.setRequisition_id(request.getParameter("requisition_id"));
		ct.setCustomer_id(request.getParameter("customer_id"));
		ct.setCustomer_name(request.getParameter("customer_name"));
		ct.setMobile(request.getParameter("mobile"));
		ct.setProduct_id(request.getParameter("product_id"));
		ct.setProduct_name(request.getParameter("product_name"));
		ct.setPack_type(request.getParameter("pack_type"));
		ct.setPack_size(request.getParameter("pack_size"));
		ct.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		ct.setBonus_id(request.getParameter("bonus_id"));
		ct.setBonus_name(request.getParameter("bonus_name"));
		ct.setOrder_pack(request.getParameter("order_pack"));
		ct.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		ct.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		ct.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		ct.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		ct.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		ct.setNeeded_date_time(request.getParameter("needed_date_time"));
		ct.setFrom_account_id(request.getParameter("from_account_id"));
		ct.setTo_account_id(request.getParameter("to_account_id"));
		ct.setSalesman_id(request.getParameter("salesman_id"));
		ct.setOrder_status(request.getParameter("order_status"));
		ct.setDelivery_status(request.getParameter("delivery_status"));
		ct.setCreated(request.getParameter("created"));
		ct.setUpdated(request.getParameter("updated"));
		ct.setCreated_by(request.getParameter("created_by"));
		ct.setUpdated_by(request.getParameter("updated_by"));
	
		String transaction_id = request.getParameter("transaction_id");

		if(action.equalsIgnoreCase("save")){
			ctdao.save(ct);
		} else if(action.equalsIgnoreCase("edit")){
			ct.setTransaction_id(transaction_id);
			ctdao.update(ct);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_CUSTOMERTRANSACTION);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("customerTransactions", ctdao.getAllCustomerTransaction());
		
		rd.forward(request, response);
	}

}
