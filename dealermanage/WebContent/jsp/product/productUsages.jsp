<jsp:include page="base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<!-- <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"> -->
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
	
<title>onlinep</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script type="text/javascript">

$(document).ready(function() {
	$('#example').DataTable();
});

function getRadioValue()
{
	var id = document.getElementsByName('product_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=edit&product_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=delete&product_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=enquiry&product_id="+idValue;
	//for enquiry [E]
	//for usages of product [S]
	var usagesPathWithIdValue = "${pageContext.request.contextPath}/ProductController?action=usages&product_id="+idValue;
	//for usages of product [E]
	
	if (idValue !=null) {
		//for update [S]
		document.getElementById('update').href = updatePathWithIdValue;
		//for update [E]
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
		//for usages of product [S]
		document.getElementById('usages').href = usagesPathWithIdValue;
		//for usages of product [E]
	} else {
		alert("Please select a ID !!");
		return false;
	}
}

//hide and display value [S]
function toggleIndications() {
    // get the lebelIndications
    var lebelIndications = document.getElementById('lebelIndications');

    // get the current value of the lebelIndications's display property
    var displaySetting = lebelIndications.style.display;

    // also get the indicationsButton button, so we can change what it says
    var indicationsButton = document.getElementById('indicationsButton');

    // now toggle the lebelIndications and the button text, depending on current state
    if (displaySetting == 'block') {
      // lebelIndications is visible. hide it
      lebelIndications.style.display = 'none';
      // change button text
      //indicationsButton.innerHTML = 'Show clock';
    }
    else {
      // lebelIndications is hidden. show it
      lebelIndications.style.display = 'block';
      // change button text
      //indicationsButton.innerHTML = 'Hide clock';
    }
}

function toggleAdultDose() {
    var lebelAdultDose = document.getElementById('lebelAdultDose');
    var adultDoseDisplaySetting = lebelAdultDose.style.display;
    var adultDoseButton = document.getElementById('adultDoseButton');
    if (adultDoseDisplaySetting == 'block') {
    	lebelAdultDose.style.display = 'none';
     } else {
   	  	lebelAdultDose.style.display = 'block';
     }
}
function toggleChildDose() {
    var lebelChildDose = document.getElementById('lebelChildDose');
    var childDoseDisplaySetting = lebelChildDose.style.display;
    var childDoseButton = document.getElementById('childDoseButton');
    if (childDoseDisplaySetting == 'block') {
    	lebelChildDose.style.display = 'none';
     } else {
    	 lebelChildDose.style.display = 'block';
     }
}
function toggleRenalDose() {
    var lebelRenalDose = document.getElementById('lebelRenalDose');
    var renalDoseDisplaySetting = lebelRenalDose.style.display;
    var renalDoseButton = document.getElementById('renalDoseButton');
    if (renalDoseDisplaySetting == 'block') {
    	lebelRenalDose.style.display = 'none';
     } else {
    	 lebelRenalDose.style.display = 'block';
     }
}
function toggleAdministrations() {
    var lebelAdministrations = document.getElementById('lebelAdministrations');
    var administrationsDisplaySetting = lebelAdministrations.style.display;
    var administrationsButton = document.getElementById('administrationsButton');
    if (administrationsDisplaySetting == 'block') {
    	lebelAdministrations.style.display = 'none';
     } else {
    	 lebelAdministrations.style.display = 'block';
     }
}
function toggleContraindications() {
    var lebelContraindications = document.getElementById('lebelContraindications');
    var contraindicationsDisplaySetting = lebelContraindications.style.display;
    var contraindicationsButton = document.getElementById('contraindicationsButton');
    if (contraindicationsDisplaySetting == 'block') {
    	lebelContraindications.style.display = 'none';
     } else {
    	 lebelContraindications.style.display = 'block';
     }
}
function toggleSideEffects() {
    var lebelSideEffects = document.getElementById('lebelSideEffects');
    var sideEffectsDisplaySetting = lebelSideEffects.style.display;
    var sideEffectsButton = document.getElementById('sideEffectsButton');
    if (sideEffectsDisplaySetting == 'block') {
    	lebelSideEffects.style.display = 'none';
     } else {
    	 lebelSideEffects.style.display = 'block';
     }
}
function togglePrecautionsWarnings() {
    var lebelPrecautionsWarnings = document.getElementById('lebelPrecautionsWarnings');
    var precautionsWarningsDisplaySetting = lebelPrecautionsWarnings.style.display;
    var precautionsWarningsButton = document.getElementById('precautionsWarningsButton');
    if (precautionsWarningsDisplaySetting == 'block') {
    	lebelPrecautionsWarnings.style.display = 'none';
     } else {
    	 lebelPrecautionsWarnings.style.display = 'block';
     }
}
function togglePregnancyCategory() {
    var lebelPregnancyCategory = document.getElementById('lebelPregnancyCategory');
    var pregnancyCategoryDisplaySetting = lebelPregnancyCategory.style.display;
    var pregnancyCategoryButton = document.getElementById('pregnancyCategoryButton');
    if (pregnancyCategoryDisplaySetting == 'block') {
    	lebelPregnancyCategory.style.display = 'none';
     } else {
    	 lebelPregnancyCategory.style.display = 'block';
     }
}
function toggleTherapeuticClass() {
    var lebelTherapeuticClass = document.getElementById('lebelTherapeuticClass');
    var therapeuticClassDisplaySetting = lebelTherapeuticClass.style.display;
    var therapeuticClassButton = document.getElementById('therapeuticClassButton');
    if (therapeuticClassDisplaySetting == 'block') {
    	lebelTherapeuticClass.style.display = 'none';
     } else {
    	 lebelTherapeuticClass.style.display = 'block';
     }
}
function toggleModeOfAction() {
    var lebelModeOfAction = document.getElementById('lebelModeOfAction');
    var modeOfActionDisplaySetting = lebelModeOfAction.style.display;
    var modeOfActionButton = document.getElementById('modeOfActionButton');
    if (modeOfActionDisplaySetting == 'block') {
    	lebelModeOfAction.style.display = 'none';
     } else {
    	 lebelModeOfAction.style.display = 'block';
     }
}
function toggleInteraction() {
    var lebelInteraction = document.getElementById('lebelInteraction');
    var interactionDisplaySetting = lebelInteraction.style.display;
    var interactionButton = document.getElementById('interactionButton');
    if (interactionDisplaySetting == 'block') {
    	lebelInteraction.style.display = 'none';
     } else {
    	 lebelInteraction.style.display = 'block';
     }
}
// hide and display value [E]

</script>
</head>
<body>

<%
String message = (String) request.getAttribute("success");
%>
	<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH"><%=message %></th>
				</tr>
				<%
				}
				%>
	</table>
	<br>
<div class="mcontent">
			<div class="titlenav">
			<ul>
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/product/product.jsp">Usages of Product</a></li>
					<li class="bread"><a href="">Dashboard > Product 
							Management > Usages of Product</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<!-- <th Class ="HeaderTH">Product ID</th> -->
				<th Class ="HeaderTH">Product Name</th>
				<th Class ="HeaderTH">Company Name</th>
				<th Class ="HeaderTH">Product Category Name</th>
				<th Class ="HeaderTH">Generic Name</th>
				<th Class ="HeaderTH">Pack Type</th>
				<th Class ="HeaderTH">Pack Size</th>
				<th Class ="HeaderTH">Pieces</th>
				<th Class ="HeaderTH">MRP</th>
				<th Class ="HeaderTH">Stock</th>
			</tr>
		</thead>
		
		<tbody>
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="product_id" id="product_id" value="${product.product_id}" onclick="javascript: getRadioValue();" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${p.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${product.product_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.company_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.product_category_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.generic_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${product.mrp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${product.stock}" /></td>
				</tr>
		</tbody>
	</table>
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<!-- <a id="usages" Class ="button" href="" onclick="javascript: getRadioValue();">usages</a> -->
					<!-- <button onclick="toggleClock()" id="clockButton">Indication</button> -->
					<a id="indicationsButton" Class ="button" onclick="toggleIndications()">Indication</a>
					<a id="adultDoseButton" Class ="button" onclick="toggleAdultDose()">Adult Dose</a>
					<a id="childDoseButton" Class ="button" onclick="toggleChildDose()">Child Dose</a>
					<a id="renalDoseButton" Class ="button" onclick="toggleRenalDose()">Renal Dose</a>
					<a id="administrationsButton" Class ="button" onclick="toggleAdministrations()">Administrations</a>
					<a id="contraindicationsButton" Class ="button" onclick="toggleContraindications()">Contraindications</a>
					<a id="sideEffectsButton" Class ="button" onclick="toggleSideEffects()">Side Effects</a>
				<br>
				<br>
				<br>
					<a id="precautionsWarningsButton" Class ="button" onclick="togglePrecautionsWarnings()">Precautions Warnings</a>
					<a id="pregnancyCategoryButton" Class ="button" onclick="togglePregnancyCategory()">Pregnancy Category</a>
					<a id="therapeuticClassButton" Class ="button" onclick="toggleTherapeuticClass()">Therapeutic Class</a>
					<a id="modeOfActionButton" Class ="button" onclick="toggleModeOfAction()">Mode Of Action</a>
					<a id="interactionButton" Class ="button" onclick="toggleInteraction()">Interaction</a>
					<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/product.jsp">Return</a></td>
				</tr>
	</table>
	
	</div>
	<br>
	<label id="lebelIndications" name="lebelIndications" style="display: none"><span style="color : red">Indications </span>
		<div class="card">
			<c:out value="${usagesProduct.indications}" />
		</div>
		<br>
	</label>
	
	<label id="lebelAdultDose" name="lebelAdultDose" style="display: none"><span style="color : red">Adult Dose </span>
		<div class="card">
			<c:out value="${usagesProduct.adult_dose}" />
		</div>
		<br>
	</label>
	
	<label id="lebelChildDose" name="lebelChildDose" style="display: none"><span style="color : red">Child Dose </span>
		<div class="card">
			<c:out value="${usagesProduct.child_dose}" />
		</div>
		<br>
	</label>
	
	<label id="lebelRenalDose" name="lebelRenalDose" style="display: none"><span style="color : red">Renal Dose </span>
		<div class="card">
			<c:out value="${usagesProduct.renal_dose}" />
		</div>
		<br>
	</label>
	
	<label id="lebelAdministrations" name="lebelAdministrations" style="display: none"><span style="color : red">Administrations </span>
		<div class="card">
			<c:out value="${usagesProduct.administrations}" />
		</div>
		<br>
	</label>
	
	<label id="lebelContraindications" name="lebelContraindications" style="display: none"><span style="color : red">Contraindications </span>
		<div class="card">
			<c:out value="${usagesProduct.contraindications}" />
		</div>
		<br>
	</label>
	
	<label id="lebelSideEffects" name="lebelSideEffects" style="display: none"><span style="color : red">Side Effects </span>
		<div class="card">
			<c:out value="${usagesProduct.side_effects}" />
		</div>
		<br>
	</label>
	
	<label id="lebelPrecautionsWarnings" name="lebelPrecautionsWarnings" style="display: none"><span style="color : red">Precautions Warnings </span>
		<div class="card">
			<c:out value="${usagesProduct.precautions_warnings}" />
		</div>
		<br>
	</label>
	
	<label id="lebelPregnancyCategory" name="lebelPregnancyCategory" style="display: none"><span style="color : red">Pregnancy Category </span>
		<div class="card">
			<c:out value="${usagesProduct.pregnancy_category}" />
		</div>
		<br>
	</label>
	
	<label id="lebelTherapeuticClass" name="lebelTherapeuticClass" style="display: none"><span style="color : red">Therapeutic Class </span>
		<div class="card">
			<c:out value="${usagesProduct.therapeutic_class}" />
		</div>
		<br>
	</label>
	
	<label id="lebelModeOfAction" name="lebelModeOfAction" style="display: none"><span style="color : red">Mode of Action </span>
		<div class="card">
			<c:out value="${usagesProduct.mode_of_action}" />
		</div>
		<br>
	</label>
	
	<label id="lebelInteraction" name="lebelInteraction" style="display: none"><span style="color : red">Interaction </span>
		<div class="card">
			<c:out value="${usagesProduct.interaction}" />
		</div>
	</label>
	
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>