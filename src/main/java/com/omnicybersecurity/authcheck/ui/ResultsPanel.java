package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.ResultsRepository;
import com.omnicybersecurity.authcheck.engine.AuthCheckEngine;
import com.omnicybersecurity.authcheck.engine.RecordStore;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;
import com.omnicybersecurity.authcheck.model.VariantResult;
import com.omnicybersecurity.authcheck.model.Verdict;
import com.omnicybersecurity.authcheck.util.Text;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.event.RowSorterEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** The Results tab: what was tested, what each identity got, and the evidence. */
public final class ResultsPanel extends JPanel {

    private final MontoyaApi api;
    private final Configuration configuration;
    private final RecordStore records;
    private final AuthCheckEngine engine;
    private final ResultsRepository repository;

    private final ResultsTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<ResultsTableModel> sorter;

    private final DefaultListModel<VariantEntry> variantListModel = new DefaultListModel<>();
    private final JList<VariantEntry> variantList = new JList<>(variantListModel);
    private final JTextArea detailArea = new JTextArea(4, 40);
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final JCheckBox autoTestToggle = new JCheckBox("Auto-test in-scope traffic");
    private final JCheckBox findingsOnly = new JCheckBox("Findings only");
    private final JLabel statusLabel = new JLabel();
    private final boolean darkTheme;

    /** Rows the table has already been told about. Event thread only. */
    private int notifiedRowCount;
    /** Set while the saved sort is being re-applied, so it is not saved back. */
    private boolean restoringSort;

    /** One row in the per-record variant list. */
    private record VariantEntry(String label, Verdict verdict, String detail, HttpRequestResponse exchange) {
        @Override
        public String toString() {
            return label;
        }
    }

    public ResultsPanel(MontoyaApi api, Configuration configuration, RecordStore records,
            AuthCheckEngine engine, ResultsRepository repository) {
        super(new BorderLayout());
        this.api = api;
        this.configuration = configuration;
        this.records = records;
        this.engine = engine;
        this.repository = repository;
        this.darkTheme = UiUtils.isDark(api);

        this.tableModel = new ResultsTableModel(records, configuration);
        this.table = new JTable(tableModel) {
            @Override
            public String getToolTipText(MouseEvent event) {
                int viewRow = rowAtPoint(event.getPoint());
                int viewColumn = columnAtPoint(event.getPoint());
                if (viewRow < 0 || viewColumn < 0) {
                    return null;
                }
                return tableModel.tooltipAt(convertRowIndexToModel(viewRow),
                        convertColumnIndexToModel(viewColumn));
            }
        };
        this.sorter = new TableRowSorter<>(tableModel);
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        buildTable();
        add(buildToolBar(), BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                UiUtils.scroll(table), buildDetailPane());
        split.setResizeWeight(0.45);
        split.setDividerLocation(320);
        add(split, BorderLayout.CENTER);

        // Results restored from the project are already in the model.
        notifiedRowCount = tableModel.getRowCount();
        wireListeners();
        applySavedSort();
        updateStatus();
    }

    // -- construction --------------------------------------------------------

    private void buildTable() {
        // Fill the viewport width. Every column but URL and Notes is capped at
        // its content width, so the spare pixels land on those two.
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.setRowSelectionAllowed(true);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowSorter(sorter);
        table.setDefaultRenderer(Verdict.class, new VerdictRenderer(darkTheme));
        table.setFillsViewportHeight(true);

        // Sort verdicts worst-first rather than by enum declaration order.
        Comparator<Verdict> bySeverity = Comparator
                .comparingInt(Verdict::severity)
                .thenComparing(Verdict::label);
        for (int column = 0; column < tableModel.getColumnCount(); column++) {
            if (tableModel.getColumnClass(column) == Verdict.class) {
                sorter.setComparator(column, bySeverity);
            }
        }
        applyColumnWidths();

        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedRecord();
            }
        });

        sorter.addRowSorterListener(event -> {
            if (event.getType() == RowSorterEvent.Type.SORT_ORDER_CHANGED) {
                rememberSort();
            }
        });
    }

    /**
     * Sizes the columns so the table fills its width with URL and Notes taking
     * the slack -- they hold the content you cannot judge at a glance, while
     * everything else has a known, short shape.
     *
     * <p>The narrow columns get a maximum width as well as a minimum: with
     * auto-resize on, spare width is shared out among the columns that can
     * still grow, so capping them is what keeps #, Datetime, Method, Status
     * and the verdicts from drifting wider than their contents.
     */
    private void applyColumnWidths() {
        int columnCount = table.getColumnCount();
        int notesColumn = columnCount - 1;

        // #, Datetime, Source, Method, URL, Status, Length
        int[] preferred = { 50, 140, 90, 70, 420, 60, 70 };
        int[] minimum = { 40, 130, 70, 55, 200, 50, 60 };
        int[] maximum = { 60, 150, 110, 80, Integer.MAX_VALUE, 70, 90 };

        for (int index = 0; index < columnCount; index++) {
            TableColumn column = table.getColumnModel().getColumn(index);
            if (index == notesColumn) {
                // Uncapped, so it shares the leftover width with URL.
                column.setPreferredWidth(300);
                column.setMinWidth(150);
                column.setMaxWidth(Integer.MAX_VALUE);
            } else if (index < preferred.length) {
                column.setMaxWidth(maximum[index]);
                column.setPreferredWidth(preferred[index]);
                column.setMinWidth(minimum[index]);
            } else {
                // A verdict column for one identity: a fixed-vocabulary label,
                // so it never needs to be wider than the longest verdict.
                column.setMaxWidth(150);
                column.setPreferredWidth(120);
                column.setMinWidth(90);
            }
        }
    }

    private JToolBar buildToolBar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);

        autoTestToggle.setSelected(configuration.settings().autoTestEnabled());
        autoTestToggle.setToolTipText("Replay every in-scope response as each identity, as traffic arrives");
        autoTestToggle.addActionListener(e -> {
            configuration.settings().autoTestEnabled(autoTestToggle.isSelected());
            configuration.settingsChanged();
            updateStatus();
        });
        bar.add(autoTestToggle);
        bar.addSeparator();

        findingsOnly.setToolTipText("Show only rows where some identity reached the resource");
        findingsOnly.addActionListener(e -> applyRowFilter());
        bar.add(findingsOnly);
        bar.addSeparator();

        JButton retest = new JButton("Retest selected");
        retest.addActionListener(e -> retestSelected());
        bar.add(retest);

        JButton sendToRepeater = new JButton("Send to Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());
        bar.add(sendToRepeater);

        JButton export = new JButton("Export CSV...");
        export.addActionListener(e -> exportCsv());
        bar.add(export);

        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> {
            records.clear();
            engine.clearDedupeCache();
            engine.resetCounters();
            clearDetail();
            updateStatus();
        });
        bar.add(clear);

        bar.add(javax.swing.Box.createHorizontalGlue());
        bar.add(statusLabel);
        return bar;
    }

    private JComponent buildDetailPane() {
        variantList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        variantList.setCellRenderer(new VariantListRenderer(darkTheme));
        variantList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedVariant();
            }
        });

        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(BorderFactory.createTitledBorder("Variants"));
        left.add(UiUtils.scroll(variantList), BorderLayout.CENTER);
        left.setPreferredSize(new Dimension(220, 200));

        JPanel detail = new JPanel(new BorderLayout());
        detail.setBorder(BorderFactory.createTitledBorder("Verdict"));
        detail.add(UiUtils.scroll(detailArea), BorderLayout.CENTER);
        detail.setPreferredSize(new Dimension(220, 120));

        JPanel leftColumn = new JPanel(new BorderLayout());
        leftColumn.add(left, BorderLayout.CENTER);
        leftColumn.add(detail, BorderLayout.SOUTH);

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                wrap("Request", requestEditor.uiComponent()),
                wrap("Response", responseEditor.uiComponent()));
        editors.setResizeWeight(0.5);

        JSplitPane pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftColumn, editors);
        pane.setResizeWeight(0.2);
        pane.setDividerLocation(260);
        return pane;
    }

    private static JComponent wrap(String title, Component component) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    private void wireListeners() {
        records.onAdded(record -> SwingUtilities.invokeLater(() -> {
            // Records arrive from worker threads faster than the event thread
            // drains them, so fire one event for however many rows appeared
            // since the last notification rather than assuming exactly one.
            int current = tableModel.getRowCount();
            if (current > notifiedRowCount) {
                tableModel.fireTableRowsInserted(notifiedRowCount, current - 1);
                notifiedRowCount = current;
            }
            updateStatus();
        }));
        records.onReset(() -> SwingUtilities.invokeLater(() -> {
            notifiedRowCount = tableModel.getRowCount();
            tableModel.fireTableDataChanged();
            updateStatus();
        }));
        configuration.onIdentitiesChanged(() -> SwingUtilities.invokeLater(this::rebuildColumns));
        configuration.onSettingsChanged(() -> SwingUtilities.invokeLater(() -> {
            autoTestToggle.setSelected(configuration.settings().autoTestEnabled());
            rebuildColumns();
            updateStatus();
        }));
        engine.onStatusChanged(() -> SwingUtilities.invokeLater(this::updateStatus));

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() == 2) {
                    sendSelectedToRepeater();
                }
            }
        });
    }

    private void rebuildColumns() {
        tableModel.rebuildColumns(true);
        Comparator<Verdict> bySeverity = Comparator
                .comparingInt(Verdict::severity)
                .thenComparing(Verdict::label);
        for (int column = 0; column < tableModel.getColumnCount(); column++) {
            if (tableModel.getColumnClass(column) == Verdict.class) {
                sorter.setComparator(column, bySeverity);
            }
        }
        applyColumnWidths();
        applySavedSort();
    }

    /**
     * Stores the current sort in the project.
     *
     * <p>Saved directly rather than through {@code settingsChanged()}: that
     * notifies listeners, one of which rebuilds the columns, which clears the
     * sort and would re-enter this method.
     */
    private void rememberSort() {
        if (restoringSort) {
            return;
        }
        List<? extends RowSorter.SortKey> keys = sorter.getSortKeys();
        if (keys.isEmpty() || keys.get(0).getSortOrder() == SortOrder.UNSORTED) {
            configuration.settings().resultsSortColumn("");
        } else {
            RowSorter.SortKey key = keys.get(0);
            configuration.settings().resultsSortColumn(tableModel.columnKey(key.getColumn()));
            configuration.settings().resultsSortAscending(key.getSortOrder() == SortOrder.ASCENDING);
        }
        configuration.save();
    }

    /** Re-applies the remembered sort, if that column still exists. */
    private void applySavedSort() {
        String columnKey = configuration.settings().resultsSortColumn();
        int column = tableModel.columnForKey(columnKey);
        restoringSort = true;
        try {
            if (column < 0) {
                // No saved sort, or the identity that column belonged to is gone.
                sorter.setSortKeys(null);
                return;
            }
            sorter.setSortKeys(List.of(new RowSorter.SortKey(column,
                    configuration.settings().resultsSortAscending()
                            ? SortOrder.ASCENDING : SortOrder.DESCENDING)));
        } finally {
            restoringSort = false;
        }
    }

    // -- selection -----------------------------------------------------------

    private List<AuthTestRecord> selectedRecords() {
        List<AuthTestRecord> selected = new ArrayList<>();
        for (int viewRow : table.getSelectedRows()) {
            AuthTestRecord record = tableModel.recordAt(table.convertRowIndexToModel(viewRow));
            if (record != null) {
                selected.add(record);
            }
        }
        return selected;
    }

    private void showSelectedRecord() {
        List<AuthTestRecord> selected = selectedRecords();
        variantListModel.clear();
        if (selected.size() != 1) {
            clearDetail();
            return;
        }
        AuthTestRecord record = selected.get(0);
        variantListModel.addElement(new VariantEntry("Baseline (as captured)", Verdict.NOT_TESTED,
                buildBaselineDetail(record), record.baseline()));
        for (VariantResult result : record.results().values()) {
            variantListModel.addElement(new VariantEntry(result.label(), result.verdict(),
                    buildVariantDetail(record, result), result.exchange()));
        }
        variantList.setSelectedIndex(pickInterestingVariant(record));
    }

    /** Selects the worst variant so the finding is on screen immediately. */
    private int pickInterestingVariant(AuthTestRecord record) {
        int best = 0;
        int bestSeverity = -1;
        int index = 1;
        for (VariantResult result : record.results().values()) {
            if (result.verdict().severity() > bestSeverity) {
                bestSeverity = result.verdict().severity();
                best = index;
            }
            index++;
        }
        return variantListModel.isEmpty() ? -1 : Math.min(best, variantListModel.size() - 1);
    }

    private String buildBaselineDetail(AuthTestRecord record) {
        StringBuilder sb = new StringBuilder();
        sb.append(record.method()).append(' ').append(record.url()).append('\n');
        sb.append("Captured from: ").append(record.source()).append('\n');
        sb.append("Baseline status: HTTP ").append(record.baselineStatus())
                .append("  (").append(record.baselineLength()).append(" bytes)\n");
        if (!record.note().isEmpty()) {
            sb.append("\nNote: ").append(record.note()).append('\n');
        }
        sb.append("\nEvery variant below is this same request, re-sent with different credentials.");
        return sb.toString();
    }

    private String buildVariantDetail(AuthTestRecord record, VariantResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(result.label()).append(": ").append(result.verdict().label()).append('\n');
        sb.append('\n').append(result.detail()).append('\n');
        if (result.exchange() != null && result.exchange().hasResponse()) {
            sb.append("\nReplay status: HTTP ").append(result.exchange().response().statusCode())
                    .append("  (").append(result.exchange().response().body().length()).append(" bytes)");
            sb.append("\nBaseline status: HTTP ").append(record.baselineStatus())
                    .append("  (").append(record.baselineLength()).append(" bytes)");
            sb.append("\nBody similarity: ").append(result.similarityPercent());
        }
        if (result.reAuthed()) {
            sb.append("\n\nThis identity was re-authenticated during the test.");
        }
        if (record.publicEndpoint() && !result.isUnauthenticated()) {
            sb.append("\n\nCaution: the unauthenticated replay also succeeded, so this endpoint looks public "
                    + "and any 'bypassed' verdict here is expected rather than a finding.");
        }
        return sb.toString();
    }

    private void showSelectedVariant() {
        VariantEntry entry = variantList.getSelectedValue();
        if (entry == null) {
            clearDetail();
            return;
        }
        detailArea.setText(entry.detail());
        detailArea.setCaretPosition(0);
        HttpRequestResponse exchange = entry.exchange();
        if (exchange == null) {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            return;
        }
        requestEditor.setRequest(exchange.request());
        responseEditor.setResponse(exchange.hasResponse() ? exchange.response() : null);
    }

    private void clearDetail() {
        detailArea.setText("");
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
    }

    // -- actions -------------------------------------------------------------

    private void retestSelected() {
        List<AuthTestRecord> selected = selectedRecords();
        if (selected.isEmpty()) {
            UiUtils.info(api, this, "Select one or more rows to retest.");
            return;
        }
        engine.retest(selected);
    }

    private void sendSelectedToRepeater() {
        VariantEntry entry = variantList.getSelectedValue();
        if (entry != null && entry.exchange() != null) {
            api.repeater().sendToRepeater(entry.exchange().request(), "AuthChk " + entry.label());
            return;
        }
        for (AuthTestRecord record : selectedRecords()) {
            api.repeater().sendToRepeater(record.baseline().request(), "AuthChk #" + record.index());
        }
    }

    private void applyRowFilter() {
        if (!findingsOnly.isSelected()) {
            sorter.setRowFilter(null);
            return;
        }
        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ResultsTableModel, ? extends Integer> entry) {
                AuthTestRecord record = tableModel.recordAt(entry.getIdentifier());
                return record != null && record.hasFinding();
            }
        });
    }

    private void exportCsv() {
        List<AuthTestRecord> all = records.snapshot();
        if (all.isEmpty()) {
            UiUtils.info(api, this, "There are no results to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("auth-check-results.csv"));
        if (chooser.showSaveDialog(UiUtils.dialogParent(api, this)) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        List<ResultsTableModel.VariantColumn> columns = tableModel.variants();

        // A long engagement's results run to thousands of rows, each carrying the
        // full verdict detail. Building and writing that on the event thread would
        // freeze Burp for as long as the disk takes.
        UiUtils.inBackground(
                () -> {
                    writeCsv(target, all, columns);
                    return all.size();
                },
                count -> UiUtils.info(api, this, "Exported " + count + " results to\n" + target),
                error -> UiUtils.error(api, this, "Could not write the CSV:\n" + UiUtils.describe(error)));
    }

    private static void writeCsv(Path target, List<AuthTestRecord> all,
            List<ResultsTableModel.VariantColumn> columns) throws IOException {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(target, StandardCharsets.UTF_8))) {
            StringBuilder header = new StringBuilder("#,Datetime,Source,Method,URL,Baseline status,Baseline length");
            for (ResultsTableModel.VariantColumn column : columns) {
                header.append(',').append(Text.csvCell(column.label()))
                        .append(',').append(Text.csvCell(column.label() + " detail"));
            }
            header.append(",Notes");
            writer.println(header);

            for (AuthTestRecord record : all) {
                StringBuilder line = new StringBuilder();
                line.append(record.index()).append(',')
                        .append(Text.csvCell(record.dateTime())).append(',')
                        .append(Text.csvCell(record.source())).append(',')
                        .append(Text.csvCell(record.method())).append(',')
                        .append(Text.csvCell(record.url())).append(',')
                        .append(record.baselineStatus()).append(',')
                        .append(record.baselineLength());
                for (ResultsTableModel.VariantColumn column : columns) {
                    VariantResult result = record.result(column.key());
                    line.append(',').append(Text.csvCell(result == null ? "" : result.verdict().label()))
                            .append(',').append(Text.csvCell(result == null ? "" : result.detail()));
                }
                line.append(',').append(Text.csvCell(record.note()));
                writer.println(line);
            }
        }
    }

    private void updateStatus() {
        int total = records.size();
        int findings = records.findingsCount();
        StringBuilder status = new StringBuilder();
        status.append(total).append(" tested, ").append(findings).append(" with findings");
        int queued = engine.queueDepth();
        if (queued > 0) {
            status.append(", ").append(queued).append(" queued");
        }
        int skipped = engine.skippedCount();
        if (skipped > 0) {
            status.append(", ").append(skipped).append(" skipped by filters");
        }
        int dropped = engine.droppedCount();
        if (dropped > 0) {
            status.append(", ").append(dropped).append(" dropped (queue full)");
        }
        int unstored = repository.droppedWrites();
        if (unstored > 0) {
            status.append(", ").append(unstored).append(" not stored to project");
        }
        status.append("   ");
        statusLabel.setText(status.toString());
    }

    /** Paints verdict cells with a severity colour. */
    private static final class VerdictRenderer extends DefaultTableCellRenderer {
        private final boolean dark;

        VerdictRenderer(boolean dark) {
            this.dark = dark;
            setHorizontalAlignment(CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            Verdict verdict = value instanceof Verdict v ? v : Verdict.NOT_TESTED;
            super.getTableCellRendererComponent(table, verdict.label(), isSelected, hasFocus, row, column);
            if (!isSelected) {
                Color background = UiUtils.verdictBackground(verdict, dark);
                setBackground(background == null ? table.getBackground() : background);
                Color foreground = UiUtils.verdictForeground(verdict, dark);
                setForeground(foreground == null ? table.getForeground() : foreground);
            }
            return this;
        }
    }

    /** Colours the variant list to match the table. */
    private static final class VariantListRenderer extends DefaultListCellRenderer {
        private final boolean dark;

        VariantListRenderer(boolean dark) {
            this.dark = dark;
        }

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof VariantEntry entry) {
                setText(entry.verdict() == Verdict.NOT_TESTED
                        ? entry.label()
                        : entry.label() + "  --  " + entry.verdict().label());
                if (!isSelected) {
                    Color background = UiUtils.verdictBackground(entry.verdict(), dark);
                    if (background != null) {
                        setBackground(background);
                        setForeground(UiUtils.verdictForeground(entry.verdict(), dark));
                    }
                }
            }
            return this;
        }
    }
}
