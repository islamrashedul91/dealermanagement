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

import com.rashed.pharmacy.model.ExpenseMain;
import com.rashed.pharmacy.dao.ExpenseMainDAO;
import com.rashed.pharmacy.model.ExpenseProduct;
import com.rashed.pharmacy.dao.ExpenseProductDAO;
import com.rashed.pharmacy.dao.ExpenseCategoryDAO;
import com.rashed.pharmacy.util.*;

public class ExpenseProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/expense/expenseProductAdd.jsp";
	private static String LIST_EXPENSEPRODUCT = "/jsp/expense/expenseProductList.jsp";
	private static String ENQUIRY = "/jsp/expense/expenseProductEnquiry.jsp";
	
	private ExpenseMainDAO emdao;
	private ExpenseProductDAO epdao;
	private ExpenseCategoryDAO ecdao;
	
	String action = "";
	String message = "";
	
       
    public ExpenseProductController() {
        super();
        
        emdao = new ExpenseMainDAO();
        epdao = new ExpenseProductDAO();
        ecdao = new ExpenseCategoryDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String expense_product_id = request.getParameter("expense_product_id");
			//rpdao.delete(requisition_product_id);
			String strOrderStatus = epdao.getSelectedOtherID(expense_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				epdao.delete(expense_product_id);
				message = "Expense " + expense_product_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Expense can not be deleted !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_EXPENSEPRODUCT;
			request.setAttribute("expenseProducts", epdao.getAllExpenseProduct());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String expense_product_id = request.getParameter("expense_product_id");
			String strExpenseId = epdao.getSelectedOtherID(expense_product_id).getExpense_id();
			String strOrderStatus = epdao.getSelectedOtherID(expense_product_id).getOrder_status();
			String strCategoryId = epdao.getSelectedOtherID(expense_product_id).getCategory_id();
			String strCategoryName = epdao.getSelectedOtherID(expense_product_id).getCategory_name();
			int intQuantity = epdao.getSelectedOtherID(expense_product_id).getQuantity();
			
			if (!strOrderStatus.equals("A")) {
				epdao.cancel(expense_product_id);
				
				message = "Expense " + expense_product_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Expense can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_EXPENSEPRODUCT;
			request.setAttribute("expenseProducts", epdao.getAllExpenseProduct());
		} else if(action.equalsIgnoreCase("approve")){
			String expense_product_id = request.getParameter("expense_product_id");
			String strExpenseId = epdao.getSelectedOtherID(expense_product_id).getExpense_id();
			String strOrderStatus = epdao.getSelectedOtherID(expense_product_id).getOrder_status();
			String strCategoryId = epdao.getSelectedOtherID(expense_product_id).getCategory_id();
			String strCategoryName = epdao.getSelectedOtherID(expense_product_id).getCategory_name();
			int intQuantity = epdao.getSelectedOtherID(expense_product_id).getQuantity();
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				epdao.approve(expense_product_id);
				
				message = "Expense " + expense_product_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_EXPENSEPRODUCT;
			request.setAttribute("expenseProducts", epdao.getAllExpenseProduct());
		} else if(action.equalsIgnoreCase("expenseCancel")){
			String expense_product_id = request.getParameter("expense_product_id");
			String strExpenseId = epdao.getSelectedOtherID(expense_product_id).getExpense_id();
			String strExpenseType = epdao.getSelectedOtherID(expense_product_id).getExpense_type();
			String date_time = epdao.getSelectedOtherID(expense_product_id).getDate_time();
			String strCategoryId = epdao.getSelectedOtherID(expense_product_id).getCategory_id();
			String strCategoryName = epdao.getSelectedOtherID(expense_product_id).getCategory_name();
			int intQuantity = epdao.getSelectedOtherID(expense_product_id).getQuantity();
			String strOrderStatus = epdao.getSelectedOtherID(expense_product_id).getOrder_status();
			String strExpenseStatus = epdao.getSelectedOtherID(expense_product_id).getExpense_status();
			double doubleTotalAmount = epdao.getSelectedOtherID(expense_product_id).getTotal_amount();
			
			if (strOrderStatus.equals("A") && !strExpenseStatus.equals("A") && !strExpenseStatus.equals("C") && !strExpenseStatus.equals("R")) {
				
				epdao.expenseCancelByExpenseProduct(expense_product_id, strExpenseId, date_time);
				
				/*String strTransactionID = ctmdao.getCustomerTransactionMainByIdDateTime(strPurchaseId, date_time).getTransaction_id();
				if(strTransactionID == null || strTransactionID.equals("")){
					tmdao.productPurchaseMainToTransactionMain(strPurchaseId, date_time);
				} else if(strTransactionID != null && !strTransactionID.equals("")){
					tmdao.returnTotalAmount(strPurchaseId, date_time);
				}*/
				
				epdao.deleteByEPIdEIdDateTime(expense_product_id, strExpenseId, date_time);
				
				message = "Expense " + expense_product_id + " Cancelled !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Expense Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strExpenseStatus.equals("C")) {
					message = "Expense Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strExpenseStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strExpenseStatus.equals("C")) {
					message = "Already Cancelled !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_EXPENSEPRODUCT;

			request.setAttribute("expenseProducts", epdao.getAllExpenseProductByMainIdDateTime(strExpenseId, date_time));
			
			request.setAttribute("expense_id", strExpenseId);
			request.setAttribute("expense_type", strExpenseType);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			
			request.setAttribute("sumTotalAmount", epdao.sumTotalAmount(strExpenseId, date_time).getTotal_amount());
			
			emdao.sumTotalAmountEP(strExpenseId, date_time);
			
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String expense_product_id = request.getParameter("expense_product_id");
			ExpenseProduct ep = epdao.getExpenseProductById(expense_product_id);
			request.setAttribute("expenseProduct", ep);
			// for get all the Category when update expense [S]
			/*request.setAttribute("allProduct", pdao.getAllProduct());*/
			request.setAttribute("allCategory", ecdao.getAllExpenseCategory());
			// for get all the Category when update expense [E]
			
			// selected other respective id during update [S]
			/*request.setAttribute("selectedCustomerId", rpdao.getSelectedOtherID(requisition_product_id).getCustomer_id());*/
			/*request.setAttribute("selectedProductId", ppdao.getSelectedOtherID(expense_product_id).getProduct_id());
			request.setAttribute("selectedBonusId", ppdao.getSelectedOtherID(expense_product_id).getBonus_id());*/
			request.setAttribute("selectedCategoryId", epdao.getSelectedOtherID(expense_product_id).getCategory_id());
			/*request.setAttribute("selectedSalesmanId", rpdao.getSelectedOtherID(requisition_product_id).getSalesman_id());*/
			// selected other respective id during update [E]
			
		} else if(action.equalsIgnoreCase("expenseProductList")){
			forward = LIST_EXPENSEPRODUCT;
			request.setAttribute("expenseProducts", epdao.getAllExpenseProduct());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String expense_product_id = request.getParameter("expense_product_id");
			ExpenseProduct ep = epdao.getExpenseProductById(expense_product_id);
			request.setAttribute("expenseProduct", ep);
		} else if(action.equalsIgnoreCase("enquiryEnquiry")){
			forward = ENQUIRY;
			String expense_product_id = request.getParameter("expense_product_id");
			ExpenseProduct ep = epdao.getExpenseProductById(expense_product_id);
			request.setAttribute("expenseProduct", ep);
		} else {
			forward = INSERT_OR_EDIT;
			
			// generated auto increment id during add [S]
			request.setAttribute("expenseProductId", epdao.getExpenseProductID().getExpense_product_id());
			// generated auto increment id during add [E]
			
			// for get all the Category when add expense [S]
			/*request.setAttribute("allProduct", pdao.getAllProduct());*/
			request.setAttribute("allCategory", ecdao.getAllExpenseCategory());
			// for get all the Category when add expense [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		ExpenseProduct ep = new ExpenseProduct();
		
		ep.setExpense_product_id(request.getParameter("expense_product_id"));
		ep.setExpense_id(request.getParameter("expense_id"));
		ep.setExpense_type(request.getParameter("expense_type"));
		ep.setDate_time(request.getParameter("date_time"));
		ep.setCategory_id(request.getParameter("category_id"));
		ep.setCategory_name(request.getParameter("category_name"));
		ep.setQuantity(Integer.parseInt(request.getParameter("quantity")));
		ep.setPrice(Double.parseDouble(request.getParameter("price")));
		ep.setTotal_price(Double.parseDouble(request.getParameter("total_price")));
		ep.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		ep.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		ep.setOrder_status(request.getParameter("order_status"));
		ep.setExpense_status(request.getParameter("expense_status"));
		ep.setCreated(request.getParameter("created"));
		ep.setUpdated(request.getParameter("updated"));
		ep.setCreated_by(request.getParameter("created_by"));
		ep.setUpdated_by(request.getParameter("updated_by"));
	
		String expense_product_id = request.getParameter("expense_product_id");
		String expense_id = request.getParameter("expense_id");
		String expense_type = request.getParameter("expense_type");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			epdao.save(ep);
		} else if(action.equalsIgnoreCase("edit")){
			ep.setExpense_product_id(expense_product_id);
			epdao.update(ep);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_EXPENSEPRODUCT);
		request.setAttribute("expenseProducts", epdao.getAllExpenseProductByMainIdDateTime(expense_id, strDateTime));
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		/*request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());*/
		// for transfer data into another page (Product Requisition) [S]
		HttpSession session1 = request.getSession();
		
		request.setAttribute("expense_id", request.getParameter("expense_id"));
		request.setAttribute("strDateTime", request.getParameter("date_time"));
		request.setAttribute("expense_type", expense_type);
		request.setAttribute("owner_name", emdao.getExpenseMainByIdDateTime(expense_id, strDateTime).getOwner_name());
		request.setAttribute("mobile", emdao.getExpenseMainByIdDateTime(expense_id, strDateTime).getMobile());
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", epdao.sumTotalAmount(expense_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
		emdao.sumTotalAmountEP(expense_id, strDateTime);
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
