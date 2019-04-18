package com.rashed.pharmacy.controller;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;

import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.TransactionProduct;
import com.rashed.pharmacy.dao.TransactionProductDAO;
import com.rashed.pharmacy.util.*;

public class TransactionProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String LIST_TRANSACTIONPRODUCT = "/jsp/order/transactionProductList.jsp";
	private static String ENQUIRY = "/jsp/order/transactionProductEnquiry.jsp";
	
	private TransactionProductDAO tpdao;
	
	String action = "";
	String message = "";
	
       
    public TransactionProductController() {
        super();
        tpdao = new TransactionProductDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String transaction_product_id = request.getParameter("transaction_product_id");
			String strOrderStatus = tpdao.getSelectedOtherID(transaction_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				tpdao.delete(transaction_product_id);
				message = "Transaction " + transaction_product_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Transaction can not be deleted !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_TRANSACTIONPRODUCT;
			request.setAttribute("transactionProducts", tpdao.getAllTransactionProduct());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("transactionProductList")){
			forward = LIST_TRANSACTIONPRODUCT;
			request.setAttribute("transactionProducts", tpdao.getAllTransactionProduct());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String transaction_product_id = request.getParameter("transaction_product_id");
			TransactionProduct tp = tpdao.getTransactionProductById(transaction_product_id);
			request.setAttribute("transactionProduct", tp);
		} else if(action.equalsIgnoreCase("enquiryEnquiry")){
			forward = ENQUIRY;
			String transaction_product_id = request.getParameter("transaction_product_id");
			TransactionProduct tp = tpdao.getTransactionProductById(transaction_product_id);
			request.setAttribute("transactionProduct", tp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
