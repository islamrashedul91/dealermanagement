package com.rashed.pharmacy.controller;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.ExpenseCategory;
import com.rashed.pharmacy.dao.ExpenseCategoryDAO;
import com.rashed.pharmacy.util.*;

public class ExpenseCategoryController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/expense/expenseCategoryAdd.jsp";
	private static String LIST_EXPENSECATEGORY = "/jsp/expense/expenseCategoryList.jsp";
	private static String ENQUIRY = "/jsp/expense/expenseCategoryEnquiry.jsp";
	private ExpenseCategoryDAO dao;
	
	String action = "";
	String message = "";
	
       
    public ExpenseCategoryController() {
        super();
        dao = new ExpenseCategoryDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String category_id = request.getParameter("category_id");
			dao.delete(category_id);
			forward=LIST_EXPENSECATEGORY;
			request.setAttribute("expenseCategorys", dao.getAllExpenseCategory());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String category_id = request.getParameter("category_id");
			ExpenseCategory ec = dao.getExpenseCategoryById(category_id);
			request.setAttribute("expenseCategory", ec);
		} else if(action.equalsIgnoreCase("expenseCategoryList")){
			forward = LIST_EXPENSECATEGORY;
			request.setAttribute("expenseCategorys", dao.getAllExpenseCategory());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String category_id = request.getParameter("category_id");
			ExpenseCategory ec = dao.getExpenseCategoryById(category_id);
			request.setAttribute("expenseCategory", ec);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("expenseCategoryId", dao.getExpenseCategoryID().getCategory_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		ExpenseCategory ec = new ExpenseCategory();
		
		ec.setCategory_id(request.getParameter("category_id"));
		ec.setCategory_name(request.getParameter("category_name"));
		ec.setDescription(request.getParameter("description"));
		ec.setCreated(request.getParameter("created"));
		ec.setUpdated(request.getParameter("updated"));
		
		String category_id = request.getParameter("category_id");
		
		if(action.equalsIgnoreCase("save")){
			dao.save(ec);
		} else if(action.equalsIgnoreCase("edit")){
			ec.setCategory_id(category_id);
			dao.update(ec);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_EXPENSECATEGORY);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("expenseCategorys", dao.getAllExpenseCategory());
		
		rd.forward(request, response);
	}

}
