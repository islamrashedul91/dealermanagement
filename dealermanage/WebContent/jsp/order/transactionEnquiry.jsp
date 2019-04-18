<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Transaction Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Transaction List > Transaction Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Transaction ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.transaction_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Transaction Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.transaction_type}" /></td>
				<td Class ="FormCellColor" colspan="2">Reason</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.reason}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Purchase ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.purchase_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.purchase_type}" /></td>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.requisition_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.product_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.pack_type}" /></td>		
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.bonus_id}" /></td>
			</tr>
			
			<tr>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.bonus_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.order_pack}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.order_quantity}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Rate Per Pieces BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.rate_per_piceces}" /></td>
				<td Class ="FormCellColor" colspan="2">Rate Per Box BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.rate_per_box}" /></td>
				<td Class ="FormCellColor" colspan="2">TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.tp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.total_tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.needed_date_time}" /></td>			
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.from_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.to_account_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.order_status == 'P' ? 'Pending' : transaction.order_status == 'A' ? 'Approved' : transaction.order_status == 'C' ? 'Cancel' : transaction.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.delivery_status == 'P' ? 'Pending' : transaction.delivery_status == 'D' ? 'Received' : transaction.delivery_status == 'C' ? 'Cancel' : transaction.delivery_status == 'R' ? 'Return' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.created}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.updated}" /></td>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transaction.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/transaction.jsp">Return</a>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>