<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script language="JavaScript">

/* function customerChng() {
	oSelectOne = frmSave.elements["brand_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('brand_name').value = finalText;

} */

function customerChng() {
	oSelectOne = frmSave.elements["customer_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[1];
	var finalTextMobile = split_selected_option_text[2];
	
	document.getElementById('customer_name').value = finalTextName;
	document.getElementById('mobile').value = finalTextMobile;

}

function productChng() {
	oSelectOne = frmSave.elements["product_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[1];
	var finalTextType = split_selected_option_text[2];
	var finalTextSize = split_selected_option_text[3];
	var finalTextPieces = split_selected_option_text[4];
	var finalTextMRP = split_selected_option_text[5];
	
	document.getElementById('product_name').value = finalTextName;
	document.getElementById('pack_type').value = finalTextType;
	document.getElementById('pack_size').value = finalTextSize;
	document.getElementById('piceces').value = finalTextPieces;
	document.getElementById('mrp_price').value = finalTextMRP;

}

function bonusChng() {
	oSelectOne = frmSave.elements["bonus_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('bonus_name').value = finalText;

}

function quantityToTotalMRP() {
	
	var quantity = document.getElementById('order_quantity').value;
	var mrp = document.getElementById('mrp_price').value;
	var quantityMultiplyMrp = quantity * mrp;
	
	//document.getElementById('total_mrp_price').value = quantityMultiplyMrp;
	document.getElementById('total_mrp_price').value = quantityMultiplyMrp.toFixed(2);

}

function discountToTotalAmount() {
	
	var discount = document.getElementById('discount_amt').value;
	var totalMrp = document.getElementById('total_mrp_price').value;
	var totalMrpMinusDiscount = totalMrp - discount;
	
	//document.getElementById('total_amount').value = totalMrpMinusDiscount;
	document.getElementById('total_amount').value = totalMrpMinusDiscount.toFixed(2);

}

</script>

</head>
<body>
<%
String action = (String) session.getAttribute("action");
System.out.println("++++++"+action);
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Sales Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Sales Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Order Management > Sales List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Sales Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Sales Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
<%
//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);
%>	
	<form action="SalesMainController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information </div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Sales ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="sales_id" id="sales_id" value="${salesId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Sales ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="sales_id" id="sales_id" value="${salesMain.sales_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field2"><span>Sales Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="sales_type" id="sales_type" value="Manual" maxlength=25 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field2"><span>Sales Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="sales_type" id="sales_type" value="${salesMain.sales_type}" maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field3"><span>Requisition ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_id" id="requisition_id" value="${requisition_id}" maxlength=25 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field3"><span>Requisition ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_id" id="requisition_id" value="${salesMain.requisition_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field4"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field4"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesMain.date_time}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="${salesMain.date_time}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field5"><span>Customer ID </span>
				<select name="customer_id" id="customer_id" class="select-field-60" onchange="customerChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allCustomer}" var="ac">
						<option value="${ac.customer_id}">${ac.customer_name}-${ac.customer_id}  -  ${ac.customer_name}  -  ${ac.mobile}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field5"><span>Customer ID </span>
				<select name="customer_id" id="customer_id" class="select-field-60" onchange="customerChng();" >
					<c:forEach items="${allCustomer}" var="ac">
						<option value="${ac.customer_id}" ${ac.customer_id == selectedCustomerId ? 'selected="selected"' : ''}>${ac.customer_id}  -  ${ac.customer_name}  -  ${ac.mobile}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field6"><span>Customer Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="customer_name" id="customer_name" value="${salesMain.customer_name}" maxlength=40 size=40 required /> 
			</label>
			
			<label for="field7"><span>Mobile <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="mobile" id="mobile" value="${salesMain.mobile}" maxlength=40 size=40 required /> 
			</label>
			
			<label for="field8"><span>Needed Date </span>
				<input type="text" class="input-field-60" name="needed_date_time" id="needed_date_time" value="${salesMain.needed_date_time}"  maxlength=14 size=40 /> 
			</label>
			
			<%-- <label for="field9"><span>From Account </span>
				<input type="text" class="input-field-60" name="from_account_id" id="from_account_id" value="${salesMain.from_account_id}"  maxlength=25 size=40 /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field9"><span>From Account <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="from_account_id" id="from_account_id" value="${mainAccountId}"  maxlength=25 size=40 required /> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field9"><span>From Account <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="from_account_id" id="from_account_id" value="${salesMain.from_account_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field10"><span>To Account </span>
				<input type="text" class="input-field-60" name="to_account_id" id="to_account_id" value="${salesMain.to_account_id}"  maxlength=25 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field11"><span>Salesman ID </span>
				<select name="salesman_id" id="salesman_id" class="select-field-60" >
					<option value="" >Select one</option>
					<c:forEach items="${allSalesman}" var="as">
						<option value="${as.salesman_id}">${as.salesman_id} - ${as.salesman_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field11"><span>Salesman ID </span>
				<select name="salesman_id" id="salesman_id" class="select-field-60" >
					<c:forEach items="${allSalesman}" var="as">
						<option value="${as.salesman_id}" ${as.salesman_id == selectedSalesmanId ? 'selected="selected"' : ''}>${as.salesman_id} - ${as.salesman_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field12"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="0.00"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field12"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="${salesMain.total_amount}"  maxlength=10 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field13"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="A">Approved</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field13"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${salesMain.order_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${salesMain.order_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="C" ${salesMain.order_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="S" ${salesMain.order_status == 'S' ? 'selected="selected"' : ''}>Success</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field14"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field14"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${salesMain.delivery_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="D" ${salesMain.delivery_status == 'D' ? 'selected="selected"' : ''}>Delivered</option>
					<option value="S" ${salesMain.delivery_status == 'S' ? 'selected="selected"' : ''}>Success</option>
					<option value="C" ${salesMain.delivery_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="R" ${salesMain.delivery_status == 'R' ? 'selected="selected"' : ''}>Return</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field15"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field15"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesMain.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${salesMain.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field16"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesMain.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${salesMain.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field16"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field17"><span>Created By </span>
				<input type="text" class="input-field-60" name="created_by" id="created_by" value="${salesMain.created_by}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field18"><span>Updated By </span>
				<input type="text" class="input-field-60" name="updated_by" id="updated_by" value="${salesMain.updated_by}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/salesMain.jsp">Return</a>
			</label>
			
	</form>
	</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->
</body>
</html>
<br>
<div>