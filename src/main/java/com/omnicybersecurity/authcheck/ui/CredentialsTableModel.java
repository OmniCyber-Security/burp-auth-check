package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Text;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Editable name/value table for one identity's credentials. These are the
 * "variables" auth scripts read through the {@code creds} binding, and they are
 * saved into the Burp project.
 *
 * <p>Values whose name looks secret are masked until the tester opts to show
 * them; masked cells are read-only so a mask can never be saved over a password.
 */
public final class CredentialsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = { "Name", "Value" };

    private final List<String[]> rows = new ArrayList<>();
    private final Runnable onChanged;
    private boolean showValues;

    public CredentialsTableModel(Runnable onChanged) {
        this.onChanged = onChanged;
    }

    public void load(Identity identity) {
        rows.clear();
        if (identity != null) {
            identity.credentialsSnapshot().forEach((key, value) -> rows.add(new String[] { key, value }));
        }
        fireTableDataChanged();
    }

    /** Writes the table back onto the identity, dropping unnamed rows. */
    public void applyTo(Identity identity) {
        if (identity == null) {
            return;
        }
        Map<String, String> updated = new LinkedHashMap<>();
        for (String[] row : rows) {
            if (!Text.isBlank(row[0])) {
                updated.put(row[0].trim(), Text.nullToEmpty(row[1]));
            }
        }
        synchronized (identity.credentials()) {
            identity.credentials().clear();
            identity.credentials().putAll(updated);
        }
    }

    public void addRow() {
        rows.add(new String[] { "", "" });
        fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        onChanged.run();
    }

    public void removeRow(int index) {
        if (index >= 0 && index < rows.size()) {
            rows.remove(index);
            fireTableRowsDeleted(index, index);
            onChanged.run();
        }
    }

    public void setShowValues(boolean value) {
        this.showValues = value;
        fireTableDataChanged();
    }

    public boolean isMasked(int rowIndex) {
        return !showValues && rowIndex >= 0 && rowIndex < rows.size() && Text.looksSecret(rows.get(rowIndex)[0]);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0 || !isMasked(rowIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        String[] row = rows.get(rowIndex);
        if (columnIndex == 0) {
            return row[0];
        }
        return isMasked(rowIndex) ? Text.mask(row[1]) : row[1];
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return;
        }
        String text = value == null ? "" : value.toString();
        if (columnIndex == 1 && isMasked(rowIndex)) {
            return;
        }
        rows.get(rowIndex)[columnIndex] = text;
        fireTableRowsUpdated(rowIndex, rowIndex);
        onChanged.run();
    }
}
