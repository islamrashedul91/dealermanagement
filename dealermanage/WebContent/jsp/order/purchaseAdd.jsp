<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script language="JavaScript">

function productChng() {
	oSelectOne = frmSave.elements["product_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[0];
	var finalTextType = split_selected_option_text[1];
	var finalTextSize = split_selected_option_text[2];
	var finalTextPieces = split_selected_option_text[3];
	var finalTextRatePerPieces = split_selected_option_text[4];
	var finalTextRatePerBox = split_selected_option_text[5];
	var finalTextTp = split_selected_option_text[6];
	
	document.getElementById('product_name').value = finalTextName;
	document.getElementById('pack_type').value = finalTextType;
	document.getElementById('pack_size').value = finalTextSize;
	document.getElementById('piceces').value = finalTextPieces;
	document.getElementById('rate_per_piceces').value = finalTextRatePerPieces;
	document.getElementById('rate_per_box').value = finalTextRatePerBox;
	document.getElementById('tp_price').value = finalTextTp;

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
	var tp = document.getElementById('tp_price').value;
	var quantityMultiplyTp = quantity * tp;
	
	document.getElementById('total_tp_price').value = quantityMultiplyTp;

}

function discountToTotalAmount() {
	
	var discount = document.getElementById('discount_amt').value;
	var totalTp = document.getElementById('total_tp_price').value;
	var totalTpMinusDiscount = totalTp - discount;
	
	document.getElementById('total_amount').value = totalTpMinusDiscount;

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
						<td class="PageHeader">Purchase Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Purchase Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Order Management > Purchase List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Purchase Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Purchase Update</td>
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
	<form action="PurchaseController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information </div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Purchase ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="purchase_id" id="purchase_id" value="${purchaseId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Purchase ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="purchase_id" id="purchase_id" value="${purchase.purchase_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field2"><span>Purchase Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="purchase_type" id="purchase_type" value="Manual" maxlength=25 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field2"><span>Purchase Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="purchase_type" id="purchase_type" value="${purchase.purchase_type}" maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field3"><span>Requisition ID </span>
				<input type="text" class="input-field-60" name="requisition_id" id="requisition_id" value="${purchase.requisition_id}" maxlength=25 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field4"><span>Product ID </span>
				<select name="product_id" id="product_id" class="select-field-60" onchange="productChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allProduct}" var="ap">
						<option value="${ap.product_id}">${ap.product_name}  -  ${ap.pack_type}  -  ${ap.pack_size}  -  ${ap.piceces}  -  ${ap.rate_per_piceces} - ${ap.rate_per_box} - ${ap.tp_price}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field4"><span>Product ID </span>
				<select name="product_id" id="product_id" class="select-field-60" onchange="productChng();" >
					<c:forEach items="${allProduct}" var="ap">
						<option value="${ap.product_id}" ${ap.product_id == selectedProductId ? 'selected="selected"' : ''}>${ap.product_name}  -  ${ap.pack_type}  -  ${ap.pack_size}  -  ${ap.piceces}  -  ${ap.rate_per_piceces} - ${ap.rate_per_box}  -  ${ap.tp_price}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field5"><span>Product Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_name" id="product_name" value="${purchase.product_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<label for="field6"><span>Pack Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_type" id="pack_type" value="${purchase.pack_type}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field7"><span>Pack Size <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_size" id="pack_size" value="${purchase.pack_size}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field8"><span>Pieces <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="piceces" id="piceces" value="${purchase.piceces}"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field9"><span>Bonus ID </span>
				<select name="bonus_id" id="bonus_id" class="select-field-60" onchange="bonusChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allBonus}" var="ab">
						<option value="${ab.bonus_id}">${ab.bonus_id}  -  ${ab.bonus_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field9"><span>Bonus ID </span>
				<select name="bonus_id" id="bonus_id" class="select-field-60" onchange="bonusChng();" >
					<c:forEach items="${allBonus}" var="ab">
						<option value="${ab.bonus_id}" ${ab.bonus_id == selectedBonusId ? 'selected="selected"' : ''}>${ab.bonus_id}  -  ${ab.bonus_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field10"><span>Bonus Name </span>
				<input type="text" class="input-field-60" readonly="readonly" name="bonus_name" id="bonus_name" value="${purchase.bonus_name}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field11"><span>Order Pack </span>
				<input type="text" class="input-field-60" name="order_pack" id="order_pack" value="${purchase.order_pack}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field12"><span>Order Quantity <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="order_quantity" id="order_quantity" value="${purchase.order_quantity}" onchange="quantityToTotalMRP();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field13"><span>Rate Per Pieces <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="rate_per_piceces" id="rate_per_piceces" value="${purchase.rate_per_piceces}" maxlength=10 size=40 required /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field14"><span>Rate Per Box <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="rate_per_box" id="rate_per_box" value="${purchase.rate_per_box}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field15"><span>TP Price <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="tp_price" id="tp_price" value="${purchase.tp_price}" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field16"><span>Total TP Price <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_tp_price" id="total_tp_price" value="${purchase.total_tp_price}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field17"><span>Discount Amount <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="discount_amt" id="discount_amt" value="${purchase.discount_amt}" onchange="discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field18"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="${purchase.total_amount}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field19"><span>Needed Date </span>
				<input type="text" class="input-field-60" name="needed_date_time" id="needed_date_time" value="${purchase.needed_date_time}"  maxlength=14 size=40 /> 
			</label>
			
			<label for="field20"><span>From Account </span>
				<input type="text" class="input-field-60" name="from_account_id" id="from_account_id" value="${purchase.from_account_id}"  maxlength=25 size=40 /> 
			</label>
			
			<label for="field21"><span>To Account </span>
				<input type="text" class="input-field-60" name="to_account_id" id="to_account_id" value="${purchase.to_account_id}"  maxlength=25 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field22"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field22"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${purchase.order_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${purchase.order_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="C" ${purchase.order_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="S" ${purchase.order_status == 'S' ? 'selected="selected"' : ''}>Success</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field23"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field23"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${purchase.delivery_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="D" ${purchase.delivery_status == 'D' ? 'selected="selected"' : ''}>Received</option>
					<option value="S" ${purchase.delivery_status == 'S' ? 'selected="selected"' : ''}>Success</option>
					<option value="C" ${purchase.delivery_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field124"><span>Created <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field124"><span>Created <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="created" id="created" value="${purchase.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field125"><span>Updated </span>
				<input type="text" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${purchase.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field125"><span>Updated <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field126"><span>Created By </span>
				<input type="text" class="input-field-60" name="created_by" id="created_by" value="${purchase.created_by}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			<div class="square-44">
			
			<label for="field127"><span>Updated By </span>
				<input type="text" class="input-field-60" name="updated_by" id="updated_by" value="${purchase.updated_by}"  maxlength=40 size=40 /> 
			</label>
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/purchase.jsp">Return</a>
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